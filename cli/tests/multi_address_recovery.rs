//! Cross-component topology changes through the production PTY client.
//! Long scheduling policies live in the pure-clock gate/catalog tests.
#[path = "support/recovery_network.rs"]
mod recovery_network;
mod support;
#[cfg(target_os = "linux")]
#[path = "../../crates/bringup/tests/support_home/mod.rs"]
mod support_home;

use recovery_network::RecoveryNetwork;
use std::{
    io::Write,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use support::*;

// Two silent addresses each retain the transport's ten-second handshake
// budget; this bounds only the necessary real I/O boundary, not retry policy.
fn wait_network(mut condition: impl FnMut() -> bool) -> bool {
    let until = Instant::now() + Duration::from_secs(35);
    while Instant::now() < until {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    condition()
}

struct Session {
    client: Client,
    output: Arc<Mutex<Vec<u8>>>,
    home: tempfile::TempDir,
}
impl Session {
    fn start(network: &RecoveryNetwork, key: &std::path::Path) -> Self {
        let home = tempfile::tempdir().unwrap();
        network.pin_qsh(home.path());
        let addresses = network.addresses();
        let client = spawn_qsh(
            &[
                "--verbose",
                "-i",
                key.to_str().unwrap(),
                &addresses[0],
                &addresses[1],
            ],
            home.path(),
        );
        let output = Arc::new(Mutex::new(Vec::new()));
        drain_into(client.master.try_clone().unwrap(), output.clone());
        let mut session = Self {
            client,
            output,
            home,
        };
        session.client.type_line("export TOPOLOGY_MARK=retained");
        session.shell("INITIAL");
        session
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.output.lock().unwrap()).into_owned()
    }
    fn frame(&self) -> terminal::Frame {
        let mut model = terminal::TerminalCore::new(80, 24);
        model.feed(&self.output.lock().unwrap());
        model.frame()
    }
    fn log(&self) -> String {
        std::fs::read_to_string(self.home.path().join("qsh/log")).unwrap_or_default()
    }
    fn wait_log(&self, needle: &str) {
        assert!(
            wait_network(|| self.log().contains(needle)),
            "missing {needle}: {}",
            self.log()
        );
    }
    fn reconnect(&mut self) {
        self.client.master.write_all(b"\x1dr").unwrap();
    }
    fn shell(&mut self, stage: &str) {
        let marker = format!("{stage}_retained");
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            self.client.master.write_all(b"\x15").unwrap();
            self.client
                .type_line(&format!("echo {stage}_$TOPOLOGY_MARK"));
            let until = Instant::now() + Duration::from_millis(500);
            while Instant::now() < until {
                if self.text().contains(&marker) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        panic!(
            "same shell did not answer {marker}: {}\n{}",
            self.text(),
            self.log()
        );
    }
    fn exit(mut self) {
        self.client.type_line("exit");
        assert_eq!(
            wait_for_exit(&mut self.client.child).unwrap().code(),
            Some(0),
            "{}",
            self.log()
        );
    }
}

#[test]
fn a_to_b_to_a_keeps_the_shell_and_cancels_ssh_after_every_path_was_tried() {
    let _serial = serialised();
    let (daemon, key) = start_daemon();
    let network = RecoveryNetwork::new(daemon.port);
    network.switch_mapping([Some(daemon.port), None]);
    network.hold_ssh(true);
    let mut session = Session::start(&network, &key);
    network.grant(session.home.path());
    let pins = std::fs::read(session.home.path().join("qsh/known_hosts")).unwrap();
    let before = network.probes();
    network.switch_mapping([None, None]);
    session.reconnect();
    assert!(
        wait_network(|| network.ssh_connections() > 0),
        "SSH never admitted: {}",
        session.log()
    );
    assert!(
        wait_until(|| {
            let frame = session.frame();
            let top: String = (0..80).map(|col| frame.cell(0, col).ch).collect();
            let active = |protocol: &str| {
                top.match_indices(protocol).any(|(col, _)| {
                    (col..col + protocol.len())
                        .all(|c| frame.cell(0, c as u16).fg == terminal::Color::Indexed(15))
                })
            };
            top.starts_with("reconnecting: 127.0.0.1 [QSH/SSH], 127.0.0.1 [QSH/SSH]")
                && active("QSH")
                && active("SSH")
                && (0..80).all(|col| frame.cell(0, col).bg == terminal::Color::Indexed(1))
        }),
        "concurrent protocol attempts must occupy a fully red row: {:?}",
        (0..80)
            .map(|col| session.frame().cell(0, col).ch)
            .collect::<String>()
    );
    let during_ssh = network.probes();
    assert!(
        during_ssh
            .iter()
            .zip(before)
            .all(|(now, before)| *now > before),
        "every path must receive QSH I/O before SSH: {before:?} -> {during_ssh:?}"
    );
    assert!(
        wait_until(|| network
            .probes()
            .iter()
            .zip(during_ssh)
            .all(|(now, before)| *now > before)),
        "all paths must continue QSH I/O during SSH: {}",
        session.log()
    );
    network.switch_mapping([None, Some(daemon.port)]);
    session.wait_log("reconnected at address 1");
    session.shell("NETWORK_B");
    assert!(
        wait_until(|| network.ssh_closed() == network.ssh_connections()),
        "losing SSH socket must close promptly"
    );
    network.hold_ssh(false);
    let admissions = network.ssh_connections();
    network.untouched();
    // B becomes a foreign daemon, while A returns. Recovery starts at B and
    // must still revisit A without resetting trust or starting another shell.
    let (foreign, _) = start_daemon();
    network.switch_mapping([Some(daemon.port), Some(foreign.port)]);
    let returning = session.log().len();
    let returning_probes = network.probes();
    session.reconnect();
    session.wait_log("reconnected at address 0");
    let log = session.log();
    let returning = &log[returning..];
    // A foreign Noise peer can look silent before its diagnostic key offer
    // completes. It must fail that path and continue to the expected server.
    let first = returning.find("ladder: TryDirect { addr: 1 }").unwrap();
    let second = returning.find("ladder: TryDirect { addr: 0 }").unwrap();
    assert!(
        first < second,
        "recovery must try B then returning A: {returning}"
    );
    assert!(
        network
            .probes()
            .iter()
            .zip(returning_probes)
            .all(|(now, before)| *now > before),
        "both returning-network paths must receive real UDP I/O"
    );
    session.shell("NETWORK_A_AGAIN");
    assert_eq!(
        std::fs::read(session.home.path().join("qsh/known_hosts")).unwrap(),
        pins
    );
    assert_eq!(
        network.ssh_connections(),
        admissions,
        "working QSH must prevent another SSH login"
    );
    network.untouched();
    assert!(session.client.child.try_wait().unwrap().is_none());
    session.exit();
}

#[test]
fn a_known_foreign_ssh_server_gets_no_auth_and_the_same_endpoint_can_retry() {
    let _serial = serialised();
    let (daemon, key) = start_daemon();
    let network = RecoveryNetwork::new(daemon.port);
    let mut session = Session::start(&network, &key);
    network.grant(session.home.path());
    network.trust_foreign_ssh(session.home.path());
    network.switch_ssh(0, true);
    let bindings = std::fs::read(session.home.path().join("qsh/ssh_bindings.json")).unwrap();
    network.switch_mapping([None, None]);
    session.reconnect();
    session.wait_log("next SSH round in 1 s; UDP keeps trying");
    assert!(
        network.foreign_connections() > 0,
        "the foreign key must actually be presented"
    );
    network.foreign_untouched();
    assert!(
        network.expected_exec() > 0,
        "a denied first SSH path must not block the authorized second path"
    );
    let before = network.expected_exec();
    network.switch_ssh(0, false);
    network.switch_ssh(1, true);
    // Only the formerly rejected endpoint now maps to the expected SSH
    // server. A new exec there proves it can authenticate again; activity
    // on the other endpoint cannot satisfy this assertion.
    assert!(
        wait_until(|| network.expected_exec() > before),
        "same-endpoint retry was blocked: {}",
        session.log()
    );
    assert_eq!(
        std::fs::read(session.home.path().join("qsh/ssh_bindings.json")).unwrap(),
        bindings
    );
    network.foreign_untouched();
    network.switch_mapping([Some(daemon.port), None]);
    session.wait_log("reconnected at address 0");
    session.shell("AFTER_WRONG_SSH");
    assert!(!session.text().contains("Install qshd"));
    session.exit();
}

#[test]
fn direct_qsh_without_binding_keeps_retrying_all_paths_without_background_questions() {
    let _serial = serialised();
    let (daemon, key) = start_daemon();
    let network = RecoveryNetwork::new(daemon.port);
    let mut session = Session::start(&network, &key);
    network.trust_foreign_ssh(session.home.path());
    let before = network.probes();
    network.switch_mapping([None, None]);
    session.reconnect();
    session.wait_log("recovery: UDP round 2");
    assert!(network
        .probes()
        .iter()
        .zip(before)
        .all(|(now, before)| *now > before));
    assert_eq!(
        network.ssh_connections(),
        0,
        "known_hosts alone cannot admit TCP"
    );
    network.untouched();
    assert!(!session.home.path().join("qsh/ssh_bindings.json").exists());
    assert!(!session.text().contains("Authorize SSH recovery"));
    assert!(!session.text().contains("password:"));
    network.switch_mapping([None, Some(daemon.port)]);
    session.wait_log("reconnected at address 1");
    session.shell("WITHOUT_BINDING");
    session.exit();
}

#[test]
fn a_to_b_to_a_dns_and_udp_results_remain_generation_bound() {
    use connect::{
        recovery_gate::{AddressId, AddressOutcome, RecoveryEpoch, SweepId},
        Address,
    };
    use qsh::{
        recovery::Recovery,
        road_catalog::{RoadCatalog, RoadWork},
    };
    let epoch = |network| RecoveryEpoch {
        connection: 7,
        network,
    };
    let a = "192.0.2.1:60000".parse().unwrap();
    let b = "192.0.2.2:60000".parse().unwrap();
    let mut catalog = RoadCatalog::new(
        vec![Address {
            host: "moving.invalid".into(),
            qsh_port: 60000,
            ssh: None,
        }],
        epoch(1),
    );
    let mut old_requests = Vec::new();
    for (generation, endpoint) in [(1, a), (2, b), (3, a)] {
        catalog.reset(epoch(generation));
        let retained = catalog.endpoints();
        let now = Duration::from_secs(generation);
        let work = catalog.refresh(now, endpoint, true);
        let request = work
            .iter()
            .find_map(|w| match w {
                RoadWork::Resolve { request, .. } => Some(*request),
                _ => None,
            })
            .unwrap();
        for &(old_epoch, old_request, old_endpoint) in &old_requests {
            catalog.resolved(old_epoch, old_request, AddressId(0), Ok(old_endpoint));
            // A repeated address cannot make an old request current again.
            catalog.resolved(
                epoch(generation),
                old_request,
                AddressId(0),
                Ok(old_endpoint),
            );
        }
        assert_eq!(
            catalog.endpoints(),
            retained,
            "stale DNS cannot replace retained candidates"
        );
        catalog.resolved(epoch(generation), request, AddressId(0), Ok(endpoint));
        assert_eq!(catalog.endpoints(), vec![(AddressId(0), endpoint)]);
        let recovery = Recovery::with_catalog(
            epoch(generation),
            catalog.address_ids(),
            catalog.endpoints(),
        );
        recovery.begin_sweep(SweepId(generation));
        for &(old_epoch, _, _) in &old_requests {
            recovery.finish(
                recovery.revision(),
                old_epoch,
                SweepId(generation),
                AddressId(0),
                AddressOutcome::Failed,
            );
        }
        assert!(!recovery.ssh_allowed());
        recovery.finish(
            recovery.revision(),
            epoch(generation),
            SweepId(generation),
            AddressId(0),
            AddressOutcome::Recovered,
        );
        assert!(!recovery.ssh_allowed());
        assert_eq!(recovery.endpoint(0), Some(endpoint));
        old_requests.push((epoch(generation), request, endpoint));
    }
}

#[test]
fn every_catalog_path_keeps_getting_probes_through_maximum_ssh_backoff() {
    use connect::{recovery_gate::RecoveryEpoch, Address};
    use qsh::road_catalog::{RoadCatalog, RoadWork};
    use transport::paths::PathTable;
    let addresses: Vec<_> = (1..=18)
        .map(|n| Address {
            host: format!("192.0.2.{n}"),
            qsh_port: 60000,
            ssh: None,
        })
        .collect();
    let active = "192.0.2.1:60000".parse().unwrap();
    let mut catalog = RoadCatalog::new(
        addresses,
        RecoveryEpoch {
            connection: 1,
            network: 1,
        },
    );
    let mut paths = PathTable::new();
    let origin = Instant::now();
    // These are real production timer inputs, advanced virtually. The catalog
    // and transport keep their normal ownership during live, SSH and backoff.
    assert_eq!(connect::reconnect::pause_after(6), Duration::from_secs(30));
    for (phase, urgent) in [("live", false), ("SSH", true), ("maximum backoff", true)] {
        let mut observed = std::collections::HashSet::new();
        let offset = match phase {
            "live" => 0,
            "SSH" => 31,
            _ => 62,
        };
        for second in offset..=offset + 30 {
            let now = Duration::from_secs(second);
            for work in catalog.refresh(now, active, urgent) {
                if let RoadWork::Publish { paths: endpoints } = work {
                    assert!(endpoints.contains(&active));
                    paths.set_paths(endpoints);
                }
            }
            for (endpoint, _) in paths.due(origin + now, urgent) {
                observed.insert(endpoint);
            }
            for (endpoint, sent) in paths.probe_times() {
                catalog.probed(endpoint, sent.duration_since(origin));
            }
        }
        assert_eq!(
            observed.len(),
            18,
            "all paths must be probed during {phase}"
        );
    }
}

/// Consent to replace a shell cannot authorize a different QSH or SSH host.
#[test]
fn replacement_consent_preserves_identity_when_the_network_changes_at_the_question() {
    let _serial = serialised();
    let (mut daemon, key) = start_daemon();
    let (foreign, _) = start_daemon();
    let network = RecoveryNetwork::new(daemon.port);
    let mut session = Session::start(&network, &key);
    network.grant(session.home.path());
    network.trust_foreign_ssh(session.home.path());
    let pins = std::fs::read(session.home.path().join("qsh/known_hosts")).unwrap();
    let bindings = std::fs::read(session.home.path().join("qsh/ssh_bindings.json")).unwrap();
    daemon.track_shell_starts();
    daemon.restart();
    session.reconnect();
    assert!(
        wait_until(|| session.text().contains("Start a new session? [Y/n]")),
        "{}",
        session.text()
    );
    assert_eq!(daemon.shell_starts(), 0);
    network.switch_mapping([Some(foreign.port), Some(foreign.port)]);
    network.switch_ssh(0, true);
    network.switch_ssh(1, true);
    session.client.master.write_all(b"yes\n").unwrap();
    session.wait_log("next SSH round in 1 s; UDP keeps trying");
    assert!(
        network.foreign_connections() > 0,
        "must encounter the changed SSH identity"
    );
    network.foreign_untouched();
    assert_eq!(daemon.shell_starts(), 0);
    assert_eq!(
        std::fs::read(session.home.path().join("qsh/known_hosts")).unwrap(),
        pins
    );
    assert_eq!(
        std::fs::read(session.home.path().join("qsh/ssh_bindings.json")).unwrap(),
        bindings
    );
    assert_eq!(session.text().matches("Key fingerprint").count(), 0);
    assert!(!session.text().contains("Authorize SSH recovery"));
    network.switch_mapping([Some(daemon.port), None]);
    assert!(
        wait_until(|| session.text().matches("\x1b[?1049h").count() == 2),
        "{}",
        session.log()
    );
    session
        .client
        .type_line("echo FRESH'AFTER'CHANGE-${TOPOLOGY_MARK:-fresh}");
    assert!(
        wait_until(|| session.text().contains("FRESHAFTERCHANGE-fresh")),
        "{}",
        session.text()
    );
    assert_eq!(daemon.shell_starts(), 1);
    session.exit();
}

/// Kill only the sandbox's qshd; its same first SSH target restarts it on
/// the configured port. Closing the loss probe revokes its SSH enrollment;
/// replacement must authenticate again without waiting on that obsolete hint.
#[test]
#[cfg(target_os = "linux")]
fn replacement_after_same_target_ssh_restart_renews_auth_promptly() {
    use support_home::{ssh_support, Sandbox};
    if ssh_support::sshd_or_skip().is_none() {
        return;
    }
    let _serial = serialised();
    let home = tempfile::tempdir().unwrap();
    let (key, public) = ssh_support::keygen_file("ed25519", home.path());
    let mut sandbox = Sandbox::start_with(std::slice::from_ref(&public));
    sandbox.cache_real_qshd(qshd::state::QSHD_VERSION);
    std::fs::create_dir_all(sandbox.home.path().join(".ssh")).unwrap();
    std::fs::write(sandbox.home.path().join(".ssh/authorized_keys"), &public).unwrap();
    let original_daemon_port = free_udp_port();
    let ready = bringup::bring_up(
        sandbox.request(original_daemon_port),
        Arc::new(knock::NoBind),
        &knock::Cancel::new(),
    )
    .unwrap();
    let first_port = ready.port_for(original_daemon_port);
    let second = UdpRelay::start(ready.port_for(original_daemon_port));
    second.cut();
    let ssh_port = sandbox.sshd.port;
    std::fs::create_dir_all(home.path().join(".ssh")).unwrap();
    std::fs::write(
        home.path().join(".ssh/known_hosts"),
        format!(
            "[127.0.0.1]:{ssh_port} {}\n",
            sandbox.sshd.host_public_key_line()
        ),
    )
    .unwrap();
    let pins = sshauth::known_hosts::KnownHosts::open(home.path().join("qsh/known_hosts"));
    let expected = sshauth::discover::discover(
        ([127, 0, 0, 1], ready.port_for(original_daemon_port)).into(),
        Duration::from_secs(1),
    )
    .unwrap();
    for port in [first_port, second.port] {
        pins.pin("127.0.0.1", port, &expected).unwrap();
    }
    let first_address = format!("127.0.0.1:{first_port},ssh={ssh_port}");
    let second_address = format!("127.0.0.1:{}", second.port);
    let client = spawn_qsh(
        &[
            "--verbose",
            "--authorize-ssh",
            "-i",
            key.to_str().unwrap(),
            &first_address,
            &second_address,
        ],
        home.path(),
    );
    let output = Arc::new(Mutex::new(Vec::new()));
    drain_into(client.master.try_clone().unwrap(), output.clone());
    let mut session = Session {
        client,
        output,
        home,
    };
    assert!(
        wait_network(|| session.text().contains("Authorize SSH recovery")),
        "{}\n{}",
        session.text(),
        session.log()
    );
    session.client.master.write_all(b"yes\n").unwrap();
    session.client.type_line("export TOPOLOGY_MARK=retained");
    session.shell("INITIAL");
    let socket = sandbox.cache().join("control.sock");
    let status_pid = || {
        let qshd::control::ControlReply::Answered(line) =
            qshd::control::client_request(&socket, &qshd::control::ControlRequest::Status).unwrap()
        else {
            panic!("fixture STATUS did not answer");
        };
        qshd::control::StatusResponse::from_line(&line).unwrap().pid
    };
    let fixture_pid = status_pid();
    // SAFETY: pidfd_open has no pointer parameters; the returned descriptor is
    // pinned to the process independently of subsequent PID reuse.
    let pidfd =
        unsafe { libc::syscall(libc::SYS_pidfd_open, fixture_pid as libc::pid_t, 0) } as i32;
    assert!(pidfd >= 0, "{}", std::io::Error::last_os_error());
    use std::os::fd::{AsRawFd, FromRawFd};
    // SAFETY: successful pidfd_open returned a new descriptor owned by this test.
    let pidfd = unsafe { std::os::fd::OwnedFd::from_raw_fd(pidfd) };
    assert_eq!(
        status_pid(),
        fixture_pid,
        "pidfd must name this private fixture daemon"
    );
    // SAFETY: the verified pidfd refers only to this sandbox daemon; no siginfo
    // is supplied and flags are zero. No personal process is signalled by PID.
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        },
        0
    );
    let mut exited = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: exited points to one pollfd and pidfd remains live during polling.
    assert_eq!(unsafe { libc::poll(&mut exited, 1, 5000) }, 1);
    session.reconnect();
    assert!(
        wait_network(|| session.text().contains("Start a new session? [Y/n]")),
        "{}\n{}",
        session.text(),
        session.log()
    );
    let accepted = Instant::now();
    session.client.master.write_all(b"y\n").unwrap();
    assert!(
        wait_network(|| session.text().matches("\x1b[?1049h").count() == 2),
        "{}\n{}",
        session.text(),
        session.log()
    );
    session
        .client
        .type_line("echo NEW'AFTER'SSH-${TOPOLOGY_MARK:-fresh}");
    assert!(
        wait_until(|| session.text().contains("NEWAFTERSSH-fresh")),
        "{}\n{}",
        session.text(),
        session.log()
    );
    let elapsed = accepted.elapsed();
    eprintln!("same-target SSH restart: accepted replacement usable in {elapsed:?}");
    assert!(
        elapsed < Duration::from_secs(3),
        "replacement reused stale SSH enrollment: {elapsed:?}\n{}",
        session.log()
    );
    session.exit();
}
