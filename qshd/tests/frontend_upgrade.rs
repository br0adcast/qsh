//! The frontend upgrade of a hosted personal daemon (#529 M2) on real
//! processes: a REAL `transport-ensure` daemon, run from a copy "A" of
//! qshd, replaces its network frontend with a newer image "B" through
//! `PREPARE-FRONTEND-UPGRADE` / `COMMIT-FRONTEND-UPGRADE`, while the host
//! keeps its pid and its own binary and every session's owner keeps its
//! own. Every claim about the process tree is read from `/proc`.
//!
//! The newer images are the stripped copy with bytes appended, labelled
//! through the debug-only `QSHD_TEST_BUILD_LABELS`, and made to fail
//! through `QSHD_TEST_IMAGE_FAULTS`, as `transport_ensure_update.rs` does.
//! Both are in the daemon's environment from its start: the frontends and
//! the self-checks it runs inherit it.
#![cfg(target_os = "linux")]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use sha2::{Digest, Sha256};

use daemon_bootstrap_protocol::{
    BusyAttemptId, BusyChoice, BusyDaemonIdentity, BusyDaemonInfo, CandidateImageIdentity,
    FrontendUpgradeAction, FrontendUpgradeConsent, FrontendUpgradeOffer, PendingBusy,
    PreservationCapability, UpgradeCase,
};
use qshd::control::{client_request_with_timeout, ControlReply, ControlRequest};
use qshd::frontend_upgrade::{
    CommitResponse, Outcome, PrepareRequest, PrepareResponse, Refusal, COMMIT_CLIENT_TIMEOUT,
    PREPARE_CLIENT_TIMEOUT,
};
use qshd::state::{SelfCheck, TEST_BUILD_LABELS_ENV, TEST_IMAGE_FAULTS_ENV};
use transport::channel::FIRST_CHANNEL_STREAM;
use transport::handshake::generate_keypair;
use transport::handshake_payload::StartKind;

mod daemon_guard;
use daemon_guard::{DaemonGuard, Finished};
mod executable_copy;
use executable_copy::copy_executable;
mod hosted_daemon;
use hosted_daemon::*;

// ---- images ----------------------------------------------------------------------

/// The stripped copy "A" a daemon runs from, in a directory of its own,
/// beside the newer images made from it.
struct Images {
    dir: tempfile::TempDir,
    a: Image,
    bytes: Vec<u8>,
}

/// One image: where it is, and what it is.
#[derive(Clone)]
struct Image {
    path: PathBuf,
    size: u64,
    checksum: String,
    build: u64,
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn images() -> Images {
    let dir = tempfile::tempdir().expect("image dir");
    let path = dir.path().join("qshd-a");
    copy_executable(Path::new(env!("CARGO_BIN_EXE_qshd")), &path);
    let status = Command::new("strip").arg(&path).status().expect(
        "this test needs `strip` (binutils): the debug qshd is larger than MAX_UPDATE_SIZE \
         until its debug info is stripped",
    );
    assert!(status.success(), "strip failed on {}", path.display());
    let bytes = std::fs::read(&path).expect("read the copy");
    assert!((bytes.len() as u64) < qshd::update::MAX_UPDATE_SIZE);
    // Isolated as the daemons are: a temporary home, and the TMPDIR the
    // tests run with.
    let home = private_temp_home();
    let out = Command::new(&path)
        .arg("self-check")
        .env("XDG_CACHE_HOME", home.path())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env("TMUX_TMPDIR", home.path())
        .env("HISTFILE", "/dev/null")
        .env_remove(TEST_BUILD_LABELS_ENV)
        .env_remove(TEST_IMAGE_FAULTS_ENV)
        .output()
        .expect("self-check runs");
    assert!(out.status.success());
    let build = SelfCheck::from_line(String::from_utf8_lossy(&out.stdout).lines().next().unwrap())
        .expect("a self-check line")
        .build;
    let a = Image {
        path,
        size: bytes.len() as u64,
        checksum: sha256_hex(&bytes),
        build,
    };
    Images { dir, a, bytes }
}

impl Images {
    /// A with `trailer` appended, to be labelled `build`.
    fn newer(&self, name: &str, trailer: &[u8], build: u64) -> Image {
        use std::os::unix::fs::PermissionsExt;
        let mut bytes = self.bytes.clone();
        bytes.extend_from_slice(trailer);
        // Written here, then copied by a child process: see
        // `executable_copy` for the "Text file busy" this avoids.
        let part = self.dir.path().join(format!("{name}.part"));
        std::fs::write(&part, &bytes).expect("write the image");
        std::fs::set_permissions(&part, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = self.dir.path().join(name);
        copy_executable(&part, &path);
        std::fs::remove_file(&part).unwrap();
        Image {
            path,
            size: bytes.len() as u64,
            checksum: sha256_hex(&bytes),
            build,
        }
    }
}

/// `QSHD_TEST_BUILD_LABELS` for `images`.
fn labels(images: &[&Image]) -> String {
    images
        .iter()
        .map(|image| format!("{}={}", image.checksum, image.build))
        .collect::<Vec<_>>()
        .join(",")
}

/// The image `pid` runs, as `/proc/<pid>/exe` names it.
fn exe_of(pid: u32) -> String {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn runs(pid: u32, image: &Image) -> bool {
    exe_of(pid) == image.path.to_string_lossy()
}

// ---- a `transport-ensure` daemon --------------------------------------------------

/// A daemon started by `transport-ensure` from A, whose control socket and
/// signed logins the test uses. Stopped, and its children checked for, on
/// drop.
struct Upgradable {
    guard: DaemonGuard,
    mark: String,
    home: tempfile::TempDir,
    sock: PathBuf,
    port: u16,
    server_pub: [u8; 32],
    key_path: PathBuf,
    host: u32,
}

impl Drop for Upgradable {
    fn drop(&mut self) {
        let _ = self.guard.finish();
        assert_no_child_left(&self.mark);
    }
}

fn start(images: &Images, labels: &str, faults: &str) -> Upgradable {
    use std::os::unix::fs::PermissionsExt;
    let home = private_temp_home();
    let (key, key_path) = write_key(home.path());
    let ssh = home.path().join(".ssh");
    std::fs::create_dir(&ssh).unwrap();
    std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o700)).unwrap();
    let authorized = ssh.join("authorized_keys");
    std::fs::write(
        &authorized,
        format!("{}\n", key.public_key().to_openssh().expect("openssh")),
    )
    .unwrap();
    std::fs::set_permissions(&authorized, std::fs::Permissions::from_mode(0o600)).unwrap();
    let port = free_udp_port();
    let mark = new_daemon_mark();
    let sock = home.path().join("qsh").join("control.sock");
    // Before the daemon exists: whatever fails from here on, it is stopped.
    let guard = DaemonGuard::new(sock.clone());
    let output = Command::new(&images.a.path)
        .args([
            "transport-ensure",
            "--name",
            "frontend-upgrade",
            "--port",
            &port.to_string(),
            "--client-pubkey",
            &BASE64.encode(generate_keypair().public),
        ])
        .env("XDG_CACHE_HOME", home.path())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env(MARK_ENV, &mark)
        .env("HISTFILE", "/dev/null")
        .env("SHELL", "/bin/sh")
        .env("TMUX_TMPDIR", home.path())
        .env_remove("TMUX")
        .env_remove("ENV")
        .env_remove("BASH_ENV")
        .env(TEST_BUILD_LABELS_ENV, labels)
        .env(TEST_IMAGE_FAULTS_ENV, faults)
        .stdin(Stdio::null())
        .output()
        .expect("`qshd transport-ensure` runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("TRANSPORT-READY "),
        "transport-ensure: {stdout} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let encoded = stdout
        .lines()
        .find_map(|line| line.strip_prefix("server-pubkey: "))
        .expect("a server-pubkey line");
    let mut server_pub = [0u8; 32];
    server_pub.copy_from_slice(&BASE64.decode(encoded.trim()).expect("base64 key"));
    let host = status(&sock).expect("the daemon answers STATUS").pid;
    let daemon = Upgradable {
        guard,
        mark,
        home,
        sock,
        port,
        server_pub,
        key_path,
        host,
    };
    assert!(runs(frontend_of(host), &images.a), "A serves first");
    daemon
}

impl Upgradable {
    fn log(&self) -> String {
        std::fs::read_to_string(self.home.path().join("qsh").join("qshd.log")).unwrap_or_default()
    }

    fn connect(&self, token: [u8; 16]) -> Session {
        Session::start(
            self.port,
            self.server_pub,
            Proof::Signature(&self.key_path),
            token,
            StartKind::Cold,
        )
        .unwrap_or_else(|| panic!("the handshake must complete; log: {}", self.log()))
    }

    /// A client's warm return to the session of `token`.
    fn come_back(&self, token: [u8; 16]) -> Session {
        Session::start(
            self.port,
            self.server_pub,
            Proof::Signature(&self.key_path),
            token,
            StartKind::Warm,
        )
        .unwrap_or_else(|| panic!("the warm return must complete; log: {}", self.log()))
    }

    /// Waits until `STATUS` counts `n` attached clients.
    fn attached(&self, n: u64) {
        assert!(
            wait_until(Duration::from_secs(20), || status(&self.sock)
                .is_some_and(|s| s.total_connections == n)),
            "STATUS never counted {n} attached client(s): {:?}",
            status(&self.sock).map(|s| s.total_connections)
        );
    }

    /// The serving frontend's identity, as `REGISTRATION-INFO` names it.
    fn identity(&self) -> BusyDaemonIdentity {
        let line = self.answered(
            &ControlRequest::RegistrationInfo([5; 32]),
            PREPARE_CLIENT_TIMEOUT,
        );
        serde_json::from_str::<qshd::control::RegistrationInfoResponse>(&line)
            .expect("a registration-info answer")
            .identity
    }

    fn server_info(&self) -> qshd::server_info::Response {
        let line = self.answered(&ControlRequest::ServerInfo([6; 32]), PREPARE_CLIENT_TIMEOUT);
        serde_json::from_str(&line).expect("a server-info answer")
    }

    fn answered(&self, request: &ControlRequest, timeout: Duration) -> String {
        match client_request_with_timeout(&self.sock, request, timeout) {
            Ok(ControlReply::Answered(line)) => line,
            other => panic!("no answer to {request:?}: {other:?}; log: {}", self.log()),
        }
    }

    fn request(&self, image: &Image, consent: Option<UpgradeCase>) -> PrepareRequest {
        let identity = self.identity();
        PrepareRequest {
            path: image.path.to_string_lossy().into_owned(),
            size: image.size,
            checksum: image.checksum.clone(),
            build: image.build,
            consent: consent.map(|case| FrontendUpgradeConsent {
                attempt: BusyAttemptId::from_bytes([9; 16]),
                identity: identity.clone(),
                candidate: CandidateImageIdentity {
                    build: image.build,
                    checksum: image.checksum.clone(),
                },
                case,
                action: FrontendUpgradeAction::ReplaceFrontend,
            }),
            identity,
        }
    }

    fn prepare_request(&self, request: PrepareRequest) -> PrepareResponse {
        let line = self.answered(
            &ControlRequest::PrepareFrontendUpgrade(request),
            PREPARE_CLIENT_TIMEOUT,
        );
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("{e}: {line}"))
    }

    fn prepare(&self, image: &Image, consent: Option<UpgradeCase>) -> PrepareResponse {
        self.prepare_request(self.request(image, consent))
    }

    /// A prepare that must hold the candidate: its receipt and outcome.
    fn prepared(&self, image: &Image, consent: Option<UpgradeCase>) -> ([u8; 16], Outcome) {
        match self.prepare(image, consent) {
            PrepareResponse::Ready { receipt, outcome } => {
                (hex::decode(receipt).unwrap().try_into().unwrap(), outcome)
            }
            other => panic!("not prepared: {other:?}; log: {}", self.log()),
        }
    }

    fn commit(&self, receipt: [u8; 16]) -> CommitResponse {
        let line = self.answered(
            &ControlRequest::CommitFrontendUpgrade(receipt),
            COMMIT_CLIENT_TIMEOUT,
        );
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("{e}: {line}"))
    }

    /// Prepare and commit `image` with nobody attached: it serves after.
    fn upgrade(&self, image: &Image) -> BusyDaemonIdentity {
        let (receipt, outcome) = self.prepared(image, None);
        assert_eq!(outcome, Outcome::Silent);
        match self.commit(receipt) {
            CommitResponse::Replaced { identity } => identity,
            other => panic!("not replaced: {other:?}; log: {}", self.log()),
        }
    }

    /// The end of a test: no zombie, exactly one frontend, and a stop that
    /// reaps every owner, frontend and the host.
    fn finish(self) {
        assert_eq!(zombies_of(self.host), Vec::<u32>::new(), "no zombie");
        assert_eq!(frontends_of(self.host).len(), 1, "one frontend");
        let owners = owners_of(self.host);
        assert_eq!(
            self.guard.finish(),
            Finished::Stopped,
            "log: {}",
            self.log()
        );
        assert!(
            wait_until(Duration::from_secs(20), || owners
                .iter()
                .all(|o| reaped(*o))
                && !running(self.host)),
            "every owner is reaped at the stop; log: {}",
            self.log()
        );
        assert_no_child_left(&self.mark);
    }
}

/// A session with a shell under `marker`, whose client then lets go and is
/// no longer counted: the shell, and its owner.
fn retained_shell(daemon: &Upgradable, token: [u8; 16], marker: &str) -> (u32, u32) {
    let session = daemon.connect(token);
    let shell = session.open_shell(marker);
    let owner = owner_of(shell, daemon.host);
    session.client.detach();
    daemon.attached(0);
    (shell, owner)
}

fn no_session_ended(daemon: &Upgradable, owner: u32) {
    let log = daemon.log();
    assert!(
        !log.contains(&format!("session owner {owner}: session ended")),
        "nothing ended the session; log: {log}"
    );
}

// ---- tests -----------------------------------------------------------------------

/// With nobody attached, B replaces A's frontend silently. The commit says
/// `Replaced` with B's identity under the host's pid and a new generation;
/// the next frontend runs B; the returning client lands in the same shell;
/// and every identity surface describes B, while `STATUS.host` still names
/// A, the host's own binary.
#[test]
fn a_silent_upgrade_keeps_the_shell_and_serves_the_new_build() {
    let _serial = serialised();
    let images = images();
    let b = images.newer("qshd-b", b"\0upgrade-b\0", images.a.build + 1);
    let daemon = start(&images, &labels(&[&b]), "");
    let token = [81; 16];
    let (shell, owner) = retained_shell(&daemon, token, "kept-81");
    let old = frontend_of(daemon.host);
    let before = daemon.identity();

    let identity = daemon.upgrade(&b);
    assert_eq!(
        (identity.build, identity.checksum.as_str()),
        (b.build, b.checksum.as_str())
    );
    assert_eq!(identity.pid, daemon.host, "the host's pid");
    assert_ne!(identity.generation, before.generation, "a new generation");
    let next = frontend_after(daemon.host, old);
    assert!(reaped(old), "the old frontend is reaped");
    assert!(runs(next, &b), "the new frontend runs B: {}", exe_of(next));

    let back = daemon.come_back(token);
    assert_eq!(back.same_shell("kept-81"), shell, "the same shell answers");
    assert_eq!(ppid(shell), Some(owner), "under the same owner");
    assert!(runs(owner, &images.a), "the owner keeps its own image");

    let status = status(&daemon.sock).expect("STATUS");
    assert_eq!(
        (status.build, status.checksum.as_str()),
        (b.build, b.checksum.as_str())
    );
    assert_eq!(status.pid, daemon.host);
    assert_eq!(status.host.expect("a hosted daemon").build, images.a.build);
    assert_eq!(daemon.identity(), identity, "REGISTRATION-INFO says B");
    let info = daemon.server_info();
    assert_eq!(
        Some(info.generation),
        identity.generation,
        "SERVER-INFO says B"
    );
    assert_eq!(
        back.client.server_generation().map(hex::encode),
        identity.generation,
        "the new frontend tells its clients B's generation in-band"
    );
    no_session_ended(&daemon, owner);
    back.client.close();
    daemon.finish();
}

/// After the upgrade a new session's owner starts from B, and the owner of
/// the session from before runs A as it did.
#[test]
fn new_sessions_run_the_new_image_and_old_owners_keep_theirs() {
    let _serial = serialised();
    let images = images();
    let b = images.newer("qshd-b", b"\0upgrade-b\0", images.a.build + 1);
    let daemon = start(&images, &labels(&[&b]), "");
    let (_, first) = retained_shell(&daemon, [82; 16], "kept-82");
    daemon.upgrade(&b);

    let fresh = daemon.connect([83; 16]);
    let shell = fresh.open_shell("fresh-83");
    let second = owner_of(shell, daemon.host);
    assert!(runs(second, &b), "a new owner runs B: {}", exe_of(second));
    assert!(
        runs(first, &images.a),
        "the old owner runs A: {}",
        exe_of(first)
    );
    fresh.client.close();
    daemon.finish();
}

/// What a rollback leaves: A serves under the identity it had, and the
/// session's client returns to its shell.
fn rolled_back_to_a(daemon: &Upgradable, images: &Images, before: &BusyDaemonIdentity) {
    assert_eq!(&daemon.identity(), before, "the previous identity serves");
    let status = status(&daemon.sock).expect("STATUS");
    assert_eq!(
        (status.build, status.checksum.as_str()),
        (images.a.build, images.a.checksum.as_str())
    );
    let frontend = frontend_of(daemon.host);
    assert!(
        runs(frontend, &images.a),
        "A's frontend serves: {}",
        exe_of(frontend)
    );
}

/// B's frontend exits before it reports ready: the commit rolls back to A,
/// which serves again, and the session survives it.
#[test]
fn a_candidate_whose_frontend_exits_rolls_back() {
    let _serial = serialised();
    let images = images();
    let b = images.newer("qshd-b", b"\0upgrade-b\0", images.a.build + 1);
    let daemon = start(
        &images,
        &labels(&[&b]),
        &format!("{}=frontend-exit", b.checksum),
    );
    let token = [84; 16];
    let (shell, owner) = retained_shell(&daemon, token, "kept-84");
    let before = daemon.identity();
    let (receipt, _) = daemon.prepared(&b, None);
    match daemon.commit(receipt) {
        CommitResponse::RolledBack { reason } => assert!(reason.contains("exited"), "{reason}"),
        other => panic!("not rolled back: {other:?}; log: {}", daemon.log()),
    }
    rolled_back_to_a(&daemon, &images, &before);
    let back = daemon.come_back(token);
    assert_eq!(back.same_shell("kept-84"), shell);
    no_session_ended(&daemon, owner);
    back.client.close();
    daemon.finish();
}

/// B's frontend serves but never says so: within the bound the commit
/// kills it and rolls back to A.
#[test]
fn a_candidate_that_never_reports_ready_rolls_back_within_the_bound() {
    let _serial = serialised();
    let images = images();
    let b = images.newer("qshd-b", b"\0upgrade-b\0", images.a.build + 1);
    let daemon = start(
        &images,
        &labels(&[&b]),
        &format!("{}=frontend-silent", b.checksum),
    );
    let token = [85; 16];
    let (shell, owner) = retained_shell(&daemon, token, "kept-85");
    let before = daemon.identity();
    let (receipt, _) = daemon.prepared(&b, None);
    let began = Instant::now();
    let answer = daemon.commit(receipt);
    let took = began.elapsed();
    assert!(
        matches!(answer, CommitResponse::RolledBack { .. }),
        "{answer:?}; log: {}",
        daemon.log()
    );
    assert!(took < Duration::from_secs(15), "rolled back after {took:?}");
    rolled_back_to_a(&daemon, &images, &before);
    let back = daemon.come_back(token);
    assert_eq!(back.same_shell("kept-85"), shell);
    no_session_ended(&daemon, owner);
    back.client.close();
    daemon.finish();
}

/// A candidate of another host revision cannot be this host's frontend:
/// only a full restart installs it, which would lose the session.
#[test]
fn a_host_revision_mismatch_is_not_preservable() {
    let _serial = serialised();
    let images = images();
    let b = images.newer("qshd-b", b"\0upgrade-b\0", images.a.build + 1);
    let daemon = start(
        &images,
        &labels(&[&b]),
        &format!("{}=host-revision=2", b.checksum),
    );
    let (shell, _) = retained_shell(&daemon, [86; 16], "kept-86");
    let frontend = frontend_of(daemon.host);
    assert_eq!(
        daemon.prepare(&b, Some(UpgradeCase::Unreachable)),
        PrepareResponse::NotPreservable {
            outcome: Outcome::Destructive {
                attached: 0,
                sessions: 1
            }
        }
    );
    // No receipt was issued: nothing to commit.
    assert_eq!(
        daemon.commit([1; 16]),
        CommitResponse::Refused {
            reason: Refusal::Unknown
        }
    );
    assert_eq!(
        frontends_of(daemon.host),
        [frontend],
        "A's frontend serves on"
    );
    assert!(running(shell));
    daemon.finish();
}

/// Another client is attached: the upgrade would disconnect it briefly, so
/// a prepare without consent asks for it, and one with it is held and
/// carried out.
#[test]
fn an_attached_client_needs_consent() {
    let _serial = serialised();
    let images = images();
    let b = images.newer("qshd-b", b"\0upgrade-b\0", images.a.build + 1);
    let daemon = start(&images, &labels(&[&b]), "");
    let token = [87; 16];
    let (shell, _) = retained_shell(&daemon, token, "kept-87");
    let other = daemon.connect([88; 16]);
    daemon.attached(1);
    let soft = Outcome::Soft { attached: 1 };
    assert_eq!(
        daemon.prepare(&b, None),
        PrepareResponse::NeedsConsent {
            outcome: soft.clone()
        }
    );
    let (receipt, outcome) = daemon.prepared(&b, Some(UpgradeCase::Soft));
    assert_eq!(outcome, soft);
    assert!(matches!(
        daemon.commit(receipt),
        CommitResponse::Replaced { .. }
    ));
    other.client.detach();
    let back = daemon.come_back(token);
    assert_eq!(back.same_shell("kept-87"), shell);
    back.client.close();
    daemon.finish();
}

/// B serves no session profile A's clients speak: the retained session's
/// client could not reach its session through it. That takes a consent to
/// exactly that case; a consent to the milder one does not do.
#[test]
fn a_retained_session_with_a_foreign_profile_is_unreachable() {
    let _serial = serialised();
    let images = images();
    let b = images.newer("qshd-b", b"\0upgrade-b\0", images.a.build + 1);
    let daemon = start(
        &images,
        &labels(&[&b]),
        &format!("{}=no-profiles", b.checksum),
    );
    retained_shell(&daemon, [89; 16], "kept-89");
    let unreachable = Outcome::Unreachable {
        attached: 0,
        sessions: 1,
        stranded: 1,
    };
    for consent in [None, Some(UpgradeCase::Soft)] {
        assert_eq!(
            daemon.prepare(&b, consent),
            PrepareResponse::NeedsConsent {
                outcome: unreachable.clone()
            },
            "{consent:?}"
        );
    }
    let (_, outcome) = daemon.prepared(&b, Some(UpgradeCase::Unreachable));
    assert_eq!(outcome, unreachable);
    daemon.finish();
}

/// The receipt was for a silent upgrade; then a client attached. The commit
/// takes the census again, finds the upgrade no longer silent, and refuses
/// without touching the frontend; the client is served on, and new
/// handshakes are admitted again.
#[test]
fn commit_refuses_when_a_client_attached_after_prepare() {
    let _serial = serialised();
    let images = images();
    let b = images.newer("qshd-b", b"\0upgrade-b\0", images.a.build + 1);
    let daemon = start(&images, &labels(&[&b]), "");
    let token = [90; 16];
    let (shell, _) = retained_shell(&daemon, token, "kept-90");
    let frontend = frontend_of(daemon.host);
    let (receipt, outcome) = daemon.prepared(&b, None);
    assert_eq!(outcome, Outcome::Silent);

    let back = daemon.come_back(token);
    daemon.attached(1);
    assert_eq!(
        daemon.commit(receipt),
        CommitResponse::Refused {
            reason: Refusal::Changed {
                outcome: Outcome::Soft { attached: 1 }
            }
        }
    );
    assert_eq!(
        frontends_of(daemon.host),
        [frontend],
        "A's frontend serves on"
    );
    assert_eq!(back.same_shell("kept-90"), shell);
    let fresh = daemon.connect([91; 16]);
    fresh.client.close();
    // The receipt is spent.
    assert_eq!(
        daemon.commit(receipt),
        CommitResponse::Refused {
            reason: Refusal::Unknown
        }
    );
    back.client.close();
    daemon.finish();
}

/// The candidate is held by descriptor from the prepare on: deleted before
/// the commit, it still starts, and the new frontend runs the deleted file.
#[test]
fn the_held_candidate_starts_after_its_file_is_deleted() {
    let _serial = serialised();
    let images = images();
    let b = images.newer("qshd-b", b"\0upgrade-b\0", images.a.build + 1);
    let daemon = start(&images, &labels(&[&b]), "");
    let token = [92; 16];
    let (shell, _) = retained_shell(&daemon, token, "kept-92");
    let old = frontend_of(daemon.host);
    let (receipt, _) = daemon.prepared(&b, None);
    std::fs::remove_file(&b.path).unwrap();
    assert!(matches!(
        daemon.commit(receipt),
        CommitResponse::Replaced { .. }
    ));
    let next = frontend_after(daemon.host, old);
    assert_eq!(exe_of(next), format!("{} (deleted)", b.path.display()));
    let back = daemon.come_back(token);
    assert_eq!(back.same_shell("kept-92"), shell);
    back.client.close();
    daemon.finish();
}

/// As M1's `killing_the_frontend_mid_paste_never_duplicates_input`, with a
/// commit in place of the kill: input inside the old frontend may be lost,
/// but only as a tail, and none is delivered twice.
#[test]
fn an_upgrade_mid_paste_never_duplicates_input() {
    let _serial = serialised();
    let images = images();
    let b = images.newer("qshd-b", b"\0upgrade-b\0", images.a.build + 1);
    let daemon = start(&images, &labels(&[&b]), "");
    let token = [93; 16];
    let session = daemon.connect(token);
    let shell = session.open_shell("kept-93");
    let owner = owner_of(shell, daemon.host);
    let record = daemon.home.path().join("pasted");
    session.send(&format!(
        "stty raw -echo; exec cat > {}\n",
        record.display()
    ));
    assert!(
        wait_until(Duration::from_secs(15), || comm(shell) == "cat"),
        "the shell becomes the recording program; saw {:?}",
        session.shell_text()
    );
    let received = || std::fs::read(&record).unwrap_or_default();
    let frontend = frontend_of(daemon.host);
    daemon.attached(1);
    let (receipt, outcome) = daemon.prepared(&b, Some(UpgradeCase::Soft));
    assert_eq!(outcome, Outcome::Soft { attached: 1 });

    // The client pastes numbered lines; once the program has taken a good
    // part, the commit starts, and the client goes on until it is done.
    let mut sent = Vec::new();
    let mut committing: Option<std::thread::JoinHandle<CommitResponse>> = None;
    for n in 0..4000u32 {
        let line = paste_line(n);
        if session
            .client
            .send_bytes(FIRST_CHANNEL_STREAM, line.clone())
            .is_err()
        {
            break;
        }
        sent.extend(line);
        if committing.is_none() && received().len() >= 4096 {
            let sock = daemon.sock.clone();
            committing = Some(std::thread::spawn(move || {
                let request = ControlRequest::CommitFrontendUpgrade(receipt);
                match client_request_with_timeout(&sock, &request, COMMIT_CLIENT_TIMEOUT) {
                    Ok(ControlReply::Answered(line)) => serde_json::from_str(&line).unwrap(),
                    other => panic!("no answer to the commit: {other:?}"),
                }
            }));
        }
        if committing.as_ref().is_some_and(|c| c.is_finished()) {
            break;
        }
        if n % 64 == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    let committing = committing.unwrap_or_else(|| {
        panic!(
            "the program takes the paste: {} bytes of {} sent; log: {}",
            received().len(),
            sent.len(),
            daemon.log()
        )
    });
    let answer = committing.join().unwrap();
    assert!(
        matches!(answer, CommitResponse::Replaced { .. }),
        "{answer:?}; log: {}",
        daemon.log()
    );
    frontend_after(daemon.host, frontend);
    session.client.detach();
    assert!(
        running(shell) && running(owner),
        "the session outlived its frontend"
    );

    // The returning client pastes lines of its own.
    let back = daemon.come_back(token);
    let mut later = Vec::new();
    for n in 0..300u32 {
        let line = paste_line(900_000 + n);
        back.client
            .send_bytes(FIRST_CHANNEL_STREAM, line.clone())
            .expect("input admitted on the new connection");
        later.extend(line);
    }
    assert!(
        wait_until(Duration::from_secs(20), || received().ends_with(&later)),
        "the returning client's paste arrives whole; the program has {} bytes; log: {}",
        received().len(),
        daemon.log()
    );
    std::thread::sleep(Duration::from_millis(500));
    let got = received();
    assert!(
        got.ends_with(&later),
        "nothing arrived after the second paste"
    );
    let first = &got[..got.len() - later.len()];
    assert!(
        sent.starts_with(first),
        "what arrived of the first paste is a leading part of it, each byte once: \
         {} bytes arrived, {} sent",
        first.len(),
        sent.len()
    );
    assert!(
        first.len() >= 4096,
        "what was taken stays taken ({} bytes)",
        first.len()
    );
    assert_eq!(ppid(shell), Some(owner), "the same program, the same owner");
    back.client.close();
    daemon.finish();
}

/// The caller closes its connection right after sending the commit: the
/// transaction runs to its end all the same. At no time do two frontends
/// run, and within 15 s exactly one does -- B's -- and the shell answers.
#[test]
fn a_commit_whose_caller_vanishes_still_ends_with_one_frontend() {
    let _serial = serialised();
    let images = images();
    let b = images.newer("qshd-b", b"\0upgrade-b\0", images.a.build + 1);
    let daemon = start(&images, &labels(&[&b]), "");
    let token = [94; 16];
    let (shell, _) = retained_shell(&daemon, token, "kept-94");
    let (receipt, _) = daemon.prepared(&b, None);
    {
        let mut stream = std::os::unix::net::UnixStream::connect(&daemon.sock).unwrap();
        stream
            .write_all(
                qshd::control::format_request(&ControlRequest::CommitFrontendUpgrade(receipt))
                    .as_bytes(),
            )
            .unwrap();
    }
    let mut most = 0;
    let one_b = wait_until(Duration::from_secs(15), || {
        let found = frontends_of(daemon.host);
        most = most.max(found.len());
        found.len() == 1 && runs(found[0], &b)
    });
    assert!(one_b, "B's frontend serves alone; log: {}", daemon.log());
    assert!(most <= 1, "two frontends ran at once");
    assert!(wait_until(Duration::from_secs(15), || status(&daemon.sock)
        .is_some_and(|s| s.build == b.build)));
    let back = daemon.come_back(token);
    assert_eq!(back.same_shell("kept-94"), shell);
    back.client.close();
    daemon.finish();
}

/// A to B to C, then C's frontend dies: the host starts C again -- the
/// image current now, not its own -- and STATUS, SERVER-INFO and
/// REGISTRATION-INFO all say C. B is older than C now, and C up to date.
#[test]
fn two_upgrades_and_a_crash_serve_the_last_image() {
    let _serial = serialised();
    let images = images();
    let b = images.newer("qshd-b", b"\0upgrade-b\0", images.a.build + 1);
    let c = images.newer("qshd-c", b"\0upgrade-c\0", b.build + 2);
    let daemon = start(&images, &labels(&[&b, &c]), "");
    let token = [95; 16];
    let (shell, _) = retained_shell(&daemon, token, "kept-95");
    daemon.upgrade(&b);
    let identity = daemon.upgrade(&c);
    let frontend = frontend_of(daemon.host);
    assert!(runs(frontend, &c));

    kill_frontend(daemon.host, frontend);
    let next = frontend_after(daemon.host, frontend);
    assert!(runs(next, &c), "the restart runs C: {}", exe_of(next));
    let status = status(&daemon.sock).expect("STATUS");
    assert_eq!(
        (status.build, status.checksum.as_str()),
        (c.build, c.checksum.as_str())
    );
    assert_eq!(daemon.identity(), identity, "REGISTRATION-INFO says C");
    assert_eq!(Some(daemon.server_info().generation), identity.generation);
    assert_eq!(
        daemon.prepare(&b, None),
        PrepareResponse::Refused {
            reason: Refusal::Older
        }
    );
    assert_eq!(daemon.prepare(&c, None), PrepareResponse::UpToDate);

    let back = daemon.come_back(token);
    assert_eq!(back.same_shell("kept-95"), shell);
    back.client.close();
    daemon.finish();
}

/// A receipt is good for one commit, and only the newest prepare's: an
/// older one, a used one and one never issued are refused, as are prepares
/// that name another frontend or another file than the one at the path.
/// (A receipt's expiry is a unit test of `host::upgrade`: its time is two
/// minutes.)
#[test]
fn a_reused_or_replaced_receipt_is_refused() {
    let _serial = serialised();
    let images = images();
    let b = images.newer("qshd-b", b"\0upgrade-b\0", images.a.build + 1);
    let daemon = start(&images, &labels(&[&b]), "");
    retained_shell(&daemon, [96; 16], "kept-96");

    let mut other = daemon.request(&b, None);
    other.identity.pid += 1;
    assert_eq!(
        daemon.prepare_request(other),
        PrepareResponse::Refused {
            reason: Refusal::Mismatch
        }
    );
    for change in 0..3 {
        let mut wrong = daemon.request(&b, None);
        match change {
            0 => wrong.size += 1,
            1 => wrong.checksum = "00".repeat(32),
            _ => wrong.build += 1,
        }
        assert!(
            matches!(
                daemon.prepare_request(wrong),
                PrepareResponse::Refused {
                    reason: Refusal::Candidate { .. }
                }
            ),
            "change {change}"
        );
    }

    let (first, _) = daemon.prepared(&b, None);
    let (second, _) = daemon.prepared(&b, None);
    let unknown = CommitResponse::Refused {
        reason: Refusal::Unknown,
    };
    assert_eq!(
        daemon.commit(first),
        unknown,
        "replaced by the newer prepare"
    );
    assert!(matches!(
        daemon.commit(second),
        CommitResponse::Replaced { .. }
    ));
    assert_eq!(daemon.commit(second), unknown, "used");
    assert_eq!(daemon.commit([7; 16]), unknown, "never issued");
    daemon.finish();
}

// ---- `transport-ensure` from the newer image ------------------------------------

/// What one `transport-ensure` run printed.
struct Ensured {
    ok: bool,
    stdout: String,
    stderr: String,
}

impl Ensured {
    /// The one `TRANSPORT-READY` body: there must be exactly one, and no
    /// `TRANSPORT-BUSY`.
    fn ready(&self) -> serde_json::Value {
        assert!(
            self.ok,
            "transport-ensure failed: {} {}",
            self.stdout, self.stderr
        );
        let ready: Vec<_> = self
            .stdout
            .lines()
            .filter_map(|line| line.strip_prefix("TRANSPORT-READY "))
            .collect();
        assert_eq!(ready.len(), 1, "one TRANSPORT-READY: {}", self.stdout);
        assert!(!self.stdout.contains("TRANSPORT-BUSY"), "{}", self.stdout);
        serde_json::from_str(ready[0]).expect("a TRANSPORT-READY body")
    }

    /// The `TRANSPORT-BUSY` record: the only line, no readiness.
    fn busy(&self) -> BusyDaemonInfo {
        assert!(
            self.ok,
            "transport-ensure failed: {} {}",
            self.stdout, self.stderr
        );
        assert!(!self.stdout.contains("TRANSPORT-READY"), "{}", self.stdout);
        let line = self
            .stdout
            .trim()
            .strip_prefix("TRANSPORT-BUSY ")
            .unwrap_or_else(|| panic!("a TRANSPORT-BUSY line: {}", self.stdout));
        serde_json::from_str(line).expect("a valid schema 3 record")
    }
}

const ATTEMPT: [u8; 16] = [0x5a; 16];

/// Runs `transport-ensure` from `image` as a login of the client whose
/// static key is `client` would: the same account, port and cache as the
/// daemon, with `extra` arguments.
fn ensure_from(
    daemon: &Upgradable,
    image: &Image,
    labels: &str,
    client: &[u8; 32],
    extra: &[&str],
) -> Ensured {
    let port = daemon.port.to_string();
    let key = BASE64.encode(client);
    let mut args = vec![
        "transport-ensure",
        "--name",
        "frontend-upgrade",
        "--port",
        &port,
        "--client-pubkey",
        &key,
    ];
    args.extend(extra);
    let home = daemon.home.path();
    let output = Command::new(&image.path)
        .args(&args)
        .env("XDG_CACHE_HOME", home)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home)
        .env(MARK_ENV, &daemon.mark)
        .env("HISTFILE", "/dev/null")
        .env("SHELL", "/bin/sh")
        .env("TMUX_TMPDIR", home)
        .env_remove("TMUX")
        .env_remove("ENV")
        .env_remove("BASH_ENV")
        .env(TEST_BUILD_LABELS_ENV, labels)
        .env_remove(TEST_IMAGE_FAULTS_ENV)
        .stdin(Stdio::null())
        .output()
        .expect("`qshd transport-ensure` runs");
    Ensured {
        ok: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn report_busy() -> Vec<String> {
    vec![
        "--report-busy".into(),
        "--busy-attempt".into(),
        BusyAttemptId::from_bytes(ATTEMPT).as_str().into(),
    ]
}

fn strs(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

impl Upgradable {
    /// A client with `private` as its static key reaches the daemon, which
    /// therefore registered it.
    fn admits(&self, private: [u8; 32], token: [u8; 16]) {
        let session = Session::start(
            self.port,
            self.server_pub,
            Proof::Allowlisted(private),
            token,
            StartKind::Cold,
        )
        .unwrap_or_else(|| panic!("the registered client is admitted; log: {}", self.log()));
        session.client.close();
    }

    /// The frontend serving is `frontend`, A's, and STATUS says A.
    fn still_a(&self, images: &Images, frontend: u32) {
        assert_eq!(
            frontends_of(self.host),
            [frontend],
            "A's frontend serves on"
        );
        assert!(runs(frontend, &images.a));
        let status = status(&self.sock).expect("STATUS");
        assert_eq!(
            (status.build, status.checksum.as_str(), status.pid),
            (images.a.build, images.a.checksum.as_str(), self.host)
        );
    }

    /// B's frontend serves under the same host, and STATUS says B.
    fn serves_b(&self, b: &Image, old: u32) {
        let next = frontend_after(self.host, old);
        assert!(runs(next, b), "the new frontend runs B: {}", exe_of(next));
        let status = status(&self.sock).expect("STATUS");
        assert_eq!(
            (status.build, status.checksum.as_str(), status.pid),
            (b.build, b.checksum.as_str(), self.host)
        );
    }
}

/// Nobody else is attached: B's login replaces the frontend silently,
/// registers its client with B's frontend, and reports ready once; the
/// session kept from before answers from the same shell.
#[test]
fn ensure_with_no_other_client_upgrades_silently_and_reports_ready() {
    let _serial = serialised();
    let images = images();
    let b = images.newer("qshd-b", b"\0upgrade-b\0", images.a.build + 1);
    let labels = labels(&[&b]);
    let daemon = start(&images, &labels, "");
    let token = [101; 16];
    let (shell, owner) = retained_shell(&daemon, token, "kept-101");
    let old = frontend_of(daemon.host);
    let client = generate_keypair();

    let ensured = ensure_from(&daemon, &b, &labels, &client.public, &[]);
    let ready = ensured.ready();
    assert_eq!(
        ready["warning"],
        serde_json::Value::Null,
        "{}",
        ensured.stdout
    );
    daemon.serves_b(&b, old);
    let status = status(&daemon.sock).unwrap();
    assert_eq!(ready["version"], status.version.as_str(), "B's version");
    assert_eq!(ready["ports"], serde_json::json!([daemon.port]));
    assert!(reaped(old), "the old frontend is reaped");

    daemon.admits(client.private, [102; 16]);
    let back = daemon.come_back(token);
    assert_eq!(back.same_shell("kept-101"), shell, "the same shell answers");
    assert_eq!(ppid(shell), Some(owner));
    no_session_ended(&daemon, owner);
    back.client.close();
    daemon.finish();
}

/// Another client is attached: a login that can ask reports a soft offer,
/// bound to the serving frontend and to B, and changes nothing.
#[test]
fn ensure_with_another_client_reports_busy_with_a_soft_offer() {
    let _serial = serialised();
    let images = images();
    let b = images.newer("qshd-b", b"\0upgrade-b\0", images.a.build + 1);
    let labels = labels(&[&b]);
    let daemon = start(&images, &labels, "");
    let (shell, _) = retained_shell(&daemon, [103; 16], "kept-103");
    let other = daemon.connect([104; 16]);
    daemon.attached(1);
    let frontend = frontend_of(daemon.host);

    let info = ensure_from(
        &daemon,
        &b,
        &labels,
        &generate_keypair().public,
        &strs(&report_busy()),
    )
    .busy();
    assert_eq!(info.schema, 3);
    assert_eq!(info.attempt, BusyAttemptId::from_bytes(ATTEMPT));
    assert_eq!(info.identity, daemon.identity());
    assert_eq!(
        info.candidate,
        CandidateImageIdentity {
            build: b.build,
            checksum: b.checksum.clone()
        }
    );
    assert_eq!(info.preservation, PreservationCapability::PreservesSessions);
    assert_eq!(
        info.upgrade,
        Some(FrontendUpgradeOffer {
            case: UpgradeCase::Soft,
            attached: 1,
            sessions: 1,
            stranded: 0
        })
    );
    assert_eq!((info.active_connections, info.sessions), (1, 1));
    assert!(info.service_restart.is_none());
    daemon.still_a(&images, frontend);
    assert!(running(shell));
    other.client.close();
    daemon.finish();
}

/// The user agrees to the soft offer: the rerun with the force decision and
/// the frontend-upgrade consent replaces the frontend and reports ready.
#[test]
fn ensure_with_soft_consent_upgrades() {
    let _serial = serialised();
    let images = images();
    let b = images.newer("qshd-b", b"\0upgrade-b\0", images.a.build + 1);
    let labels = labels(&[&b]);
    let daemon = start(&images, &labels, "");
    let token = [105; 16];
    let (shell, owner) = retained_shell(&daemon, token, "kept-105");
    let other = daemon.connect([106; 16]);
    daemon.attached(1);
    let old = frontend_of(daemon.host);
    let client = generate_keypair();

    let info = ensure_from(&daemon, &b, &labels, &client.public, &strs(&report_busy())).busy();
    let consent = info.confirm_frontend_upgrade().expect("an upgrade offer");
    assert_eq!(consent.case, UpgradeCase::Soft);
    let decision = PendingBusy::new(info)
        .expect("a valid record")
        .decide(BusyChoice::ForceUpdate);
    let mut args = report_busy();
    args.extend([
        "--busy-decision".into(),
        serde_json::to_string(&decision).unwrap(),
        "--frontend-upgrade-consent".into(),
        serde_json::to_string(&consent).unwrap(),
    ]);
    let ensured = ensure_from(&daemon, &b, &labels, &client.public, &strs(&args));
    let ready = ensured.ready();
    assert_eq!(
        ready["warning"],
        serde_json::Value::Null,
        "{}",
        ensured.stdout
    );
    daemon.serves_b(&b, old);
    daemon.admits(client.private, [107; 16]);

    other.client.detach();
    let back = daemon.come_back(token);
    assert_eq!(back.same_shell("kept-105"), shell);
    no_session_ended(&daemon, owner);
    back.client.close();
    daemon.finish();
}

/// A login that cannot ask (no `--report-busy`) never disconnects the other
/// client: it registers with A's frontend and says why it kept it.
#[test]
fn ensure_without_report_busy_keeps_the_old_daemon_and_warns() {
    let _serial = serialised();
    let images = images();
    let b = images.newer("qshd-b", b"\0upgrade-b\0", images.a.build + 1);
    let labels = labels(&[&b]);
    let daemon = start(&images, &labels, "");
    let (shell, _) = retained_shell(&daemon, [108; 16], "kept-108");
    let other = daemon.connect([109; 16]);
    daemon.attached(1);
    let frontend = frontend_of(daemon.host);
    let before = daemon.identity();
    let client = generate_keypair();

    let ready = ensure_from(&daemon, &b, &labels, &client.public, &[]).ready();
    let warning = ready["warning"].as_str().expect("a warning");
    assert!(warning.contains("1 other client(s)"), "{warning}");
    daemon.still_a(&images, frontend);
    assert_eq!(daemon.identity(), before);
    daemon.attached(1);
    daemon.admits(client.private, [110; 16]);
    assert!(running(shell));
    other.client.close();
    daemon.finish();
}

/// B cannot be this host's frontend, and the daemon keeps a session whose
/// client let go. Before M2 that was a silent STOP that lost it. Now a
/// login that cannot ask keeps the daemon and warns, and one that can is
/// asked about the destructive restart, which names the retained session.
#[test]
fn ensure_against_an_incompatible_host_with_only_retained_sessions_asks_destructive() {
    let _serial = serialised();
    let images = images();
    let b = images.newer("qshd-b", b"\0upgrade-b\0", images.a.build + 1);
    let labels = labels(&[&b]);
    let daemon = start(&images, &labels, &format!("{}=host-revision=2", b.checksum));
    let (shell, owner) = retained_shell(&daemon, [111; 16], "kept-111");
    let frontend = frontend_of(daemon.host);

    let ready = ensure_from(&daemon, &b, &labels, &generate_keypair().public, &[]).ready();
    let warning = ready["warning"].as_str().expect("a warning");
    assert!(warning.contains("1 session(s)"), "{warning}");
    daemon.still_a(&images, frontend);

    let info = ensure_from(
        &daemon,
        &b,
        &labels,
        &generate_keypair().public,
        &strs(&report_busy()),
    )
    .busy();
    assert_eq!((info.active_connections, info.sessions), (0, 1));
    assert_eq!(info.preservation, PreservationCapability::Unknown);
    assert_eq!(info.upgrade, None);
    assert_eq!(info.identity, daemon.identity());
    daemon.still_a(&images, frontend);
    assert!(running(shell) && running(owner), "the session is kept");
    no_session_ended(&daemon, owner);
    daemon.finish();
}

/// B cannot be this host's frontend, and there is no session to lose: the
/// login restarts the daemon from B without asking, as before M2.
#[test]
fn ensure_against_an_incompatible_host_without_sessions_restarts_silently() {
    let _serial = serialised();
    let images = images();
    let b = images.newer("qshd-b", b"\0upgrade-b\0", images.a.build + 1);
    let labels = labels(&[&b]);
    let daemon = start(&images, &labels, &format!("{}=host-revision=2", b.checksum));
    let old_host = daemon.host;

    let ready = ensure_from(
        &daemon,
        &b,
        &labels,
        &generate_keypair().public,
        &strs(&report_busy()),
    )
    .ready();
    assert_eq!(ready["warning"], serde_json::Value::Null);
    let status = status(&daemon.sock).expect("the new daemon answers");
    assert_ne!(status.pid, old_host, "a new daemon");
    assert!(runs(status.pid, &b), "it runs B: {}", exe_of(status.pid));
    assert_eq!(
        (status.build, status.checksum.as_str()),
        (b.build, b.checksum.as_str())
    );
    assert!(
        wait_until(Duration::from_secs(10), || reaped(old_host)),
        "the old daemon is gone"
    );
    assert_eq!(daemon.guard.finish(), Finished::Stopped);
}

/// B's frontend exits before it reports ready: the daemon rolls back to A,
/// and the login registers its client with A's frontend and warns.
#[test]
fn ensure_after_a_rollback_registers_with_the_old_daemon_and_warns() {
    let _serial = serialised();
    let images = images();
    let b = images.newer("qshd-b", b"\0upgrade-b\0", images.a.build + 1);
    let labels = labels(&[&b]);
    let daemon = start(&images, &labels, &format!("{}=frontend-exit", b.checksum));
    let token = [112; 16];
    let (shell, owner) = retained_shell(&daemon, token, "kept-112");
    let before = daemon.identity();
    let client = generate_keypair();

    let ready = ensure_from(&daemon, &b, &labels, &client.public, &[]).ready();
    let warning = ready["warning"].as_str().expect("a warning");
    assert!(warning.contains("did not start"), "{warning}");
    rolled_back_to_a(&daemon, &images, &before);
    daemon.admits(client.private, [113; 16]);
    let back = daemon.come_back(token);
    assert_eq!(back.same_shell("kept-112"), shell);
    no_session_ended(&daemon, owner);
    back.client.close();
    daemon.finish();
}

// ---- `qshd reload`, against a `serve` daemon ------------------------------------

/// A personal `qshd serve` daemon run from the path P of copy A, as the
/// systemd user unit runs `/usr/bin/qshd`: `qshd reload --port` asks it to
/// replace its frontend from P, whatever a package manager renamed onto it
/// since. Stopped with `SIGTERM`, and its children checked for, at the end.
struct Served {
    child: std::process::Child,
    mark: String,
    home: tempfile::TempDir,
    /// The path the daemon was started from.
    path: PathBuf,
    port: u16,
    server_pub: [u8; 32],
    key_path: PathBuf,
    host: u32,
}

impl Drop for Served {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        assert_no_child_left(&self.mark);
    }
}

fn serve(images: &Images, labels: &str, faults: &str) -> Served {
    use std::io::{BufRead, BufReader, Read};
    let home = private_temp_home();
    let (key, key_path) = write_key(home.path());
    let authorized_keys = home.path().join("authorized_keys");
    std::fs::write(
        &authorized_keys,
        format!("{}\n", key.public_key().to_openssh().expect("openssh")),
    )
    .unwrap();
    let port = free_udp_port();
    let mark = new_daemon_mark();
    let mut child = Command::new(&images.a.path)
        .args([
            "serve",
            "--port",
            &port.to_string(),
            "--authorized-keys",
            authorized_keys.to_str().expect("utf-8 path"),
            "--host-key",
            home.path().join("host_key").to_str().expect("utf-8 path"),
        ])
        .env("XDG_CACHE_HOME", home.path())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env(MARK_ENV, &mark)
        .env("HISTFILE", "/dev/null")
        .env("SHELL", "/bin/sh")
        .env("TMUX_TMPDIR", home.path())
        .env_remove("TMUX")
        .env_remove("ENV")
        .env_remove("BASH_ENV")
        .env(TEST_BUILD_LABELS_ENV, labels)
        .env(TEST_IMAGE_FAULTS_ENV, faults)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("`qshd serve` spawns");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut line = String::new();
    reader.read_line(&mut line).expect("server-pubkey line");
    let encoded = line
        .strip_prefix("server-pubkey: ")
        .unwrap_or_else(|| panic!("expected a server-pubkey line, got {line:?}"))
        .trim_end();
    let mut server_pub = [0u8; 32];
    server_pub.copy_from_slice(&BASE64.decode(encoded).expect("base64 key"));
    // Drain the rest so the daemon never blocks on a full pipe.
    std::thread::spawn(move || {
        let mut sink = Vec::new();
        let _ = reader.read_to_end(&mut sink);
    });
    let host = child.id();
    let daemon = Served {
        child,
        mark,
        home,
        path: images.a.path.clone(),
        port,
        server_pub,
        key_path,
        host,
    };
    assert!(runs(frontend_of(host), &images.a), "A serves first");
    // The reload socket is bound once the daemon serves.
    let sock = daemon.reload_socket();
    assert!(
        wait_until(Duration::from_secs(15), || sock.exists()),
        "the daemon binds {}; log: {}",
        sock.display(),
        daemon.log()
    );
    daemon
}

/// What one `qshd reload` printed, and how it exited.
struct Reloaded {
    code: Option<i32>,
    output: String,
}

impl Served {
    fn log(&self) -> String {
        std::fs::read_to_string(self.home.path().join("qsh").join("qshd.log")).unwrap_or_default()
    }

    fn reload_socket(&self) -> PathBuf {
        self.home
            .path()
            .join("qsh")
            .join(format!("qshd-serve-{}.sock", self.port))
    }

    fn connect(&self, token: [u8; 16]) -> Session {
        Session::start(
            self.port,
            self.server_pub,
            Proof::Signature(&self.key_path),
            token,
            StartKind::Cold,
        )
        .unwrap_or_else(|| panic!("the handshake must complete; log: {}", self.log()))
    }

    fn come_back(&self, token: [u8; 16]) -> Session {
        Session::start(
            self.port,
            self.server_pub,
            Proof::Signature(&self.key_path),
            token,
            StartKind::Warm,
        )
        .unwrap_or_else(|| panic!("the warm return must complete; log: {}", self.log()))
    }

    /// `<qshd> reload --port <port>`, run from `qshd`, in the daemon's home.
    fn reload_with(&self, qshd: &Path) -> Reloaded {
        reload_in(qshd, self.home.path(), self.port)
    }

    /// `P reload --port <port>`: the installed binary asks, as `ExecReload`.
    fn reload(&self) -> Reloaded {
        self.reload_with(&self.path)
    }

    /// Rename `image` onto P, as a package manager installs a file.
    fn install(&self, image: &Image) {
        std::fs::rename(&image.path, &self.path).expect("rename onto P");
    }

    /// SIGTERM; the daemon exits on its own and reaps every child.
    fn finish(mut self) {
        assert_eq!(zombies_of(self.host), Vec::<u32>::new(), "no zombie");
        assert_eq!(frontends_of(self.host).len(), 1, "one frontend");
        let owners = owners_of(self.host);
        unsafe { libc::kill(self.host as i32, libc::SIGTERM) };
        let deadline = Instant::now() + Duration::from_secs(40);
        let status = loop {
            if let Some(status) = self.child.try_wait().expect("waiting for the daemon") {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "the daemon did not stop; log: {}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(status.success(), "{status:?}; log: {}", self.log());
        assert!(owners.iter().all(|o| reaped(*o)), "every owner is reaped");
        assert!(
            !self.reload_socket().exists(),
            "the reload socket goes with the daemon"
        );
        assert_no_child_left(&self.mark);
    }
}

fn reload_in(qshd: &Path, home: &Path, port: u16) -> Reloaded {
    let out = Command::new(qshd)
        .args(["reload", "--port", &port.to_string()])
        .env("XDG_CACHE_HOME", home)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home)
        .env("HISTFILE", "/dev/null")
        .env_remove(TEST_BUILD_LABELS_ENV)
        .env_remove(TEST_IMAGE_FAULTS_ENV)
        .stdin(Stdio::null())
        .output()
        .expect("`qshd reload` runs");
    Reloaded {
        code: out.status.code(),
        output: format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    }
}

/// sha256 of the image `pid` runs, read through `/proc/<pid>/exe`.
fn image_of(pid: u32) -> String {
    sha256_hex(&std::fs::read(format!("/proc/{pid}/exe")).unwrap_or_default())
}

/// A session with a shell under `marker`, whose client then lets go.
fn served_shell(daemon: &Served, token: [u8; 16], marker: &str) -> (u32, u32) {
    let session = daemon.connect(token);
    let shell = session.open_shell(marker);
    let owner = owner_of(shell, daemon.host);
    session.client.detach();
    (shell, owner)
}

/// After a package upgrade renamed B onto P, `P reload` replaces the
/// frontend with B -- read from P, the path the daemon was started from,
/// not from its own (now deleted) image -- and the same shell answers.
#[test]
fn reload_replaces_the_frontend_from_the_start_path() {
    let _serial = serialised();
    let images = images();
    let b = images.newer("qshd-b", b"\0reload-b\0", images.a.build + 1);
    let daemon = serve(&images, &labels(&[&b]), "");
    let token = [120; 16];
    let (shell, owner) = served_shell(&daemon, token, "kept-120");
    let old = frontend_of(daemon.host);

    daemon.install(&b);
    let reloaded = daemon.reload();
    assert_eq!(
        reloaded.code,
        Some(0),
        "{}; log: {}",
        reloaded.output,
        daemon.log()
    );
    assert!(
        reloaded.output.contains(&format!(
            "qshd frontend replaced by build {}; sessions kept",
            b.build
        )),
        "{}",
        reloaded.output
    );
    let next = frontend_after(daemon.host, old);
    assert!(reaped(old), "the old frontend is reaped");
    assert_eq!(image_of(next), b.checksum, "the new frontend runs B");
    assert_eq!(exe_of(next), daemon.path.to_string_lossy(), "from P");
    assert!(running(daemon.host), "the host is the same process");

    let back = daemon.come_back(token);
    assert_eq!(back.same_shell("kept-120"), shell, "the same shell answers");
    assert_eq!(ppid(shell), Some(owner), "under the same owner");
    back.client.close();
    daemon.finish();
}

/// A reinstall of the same bytes, and a reload with nothing installed at
/// all, are successful no-ops: the frontend keeps running.
#[test]
fn reload_with_an_identical_binary_is_a_no_op() {
    let _serial = serialised();
    let images = images();
    let same = images.newer("qshd-same", b"", images.a.build);
    assert_eq!(same.checksum, images.a.checksum);
    let daemon = serve(&images, "", "");
    let (shell, _) = served_shell(&daemon, [121; 16], "kept-121");
    let frontend = frontend_of(daemon.host);
    for installed in [false, true] {
        if installed {
            daemon.install(&same);
        }
        let reloaded = daemon.reload();
        assert_eq!(reloaded.code, Some(0), "{}", reloaded.output);
        assert!(
            reloaded.output.contains("qshd is up to date"),
            "{}",
            reloaded.output
        );
        assert_eq!(frontends_of(daemon.host), [frontend], "the same frontend");
    }
    assert!(running(shell));
    daemon.finish();
}

/// An older binary at P (a package downgrade), an unreadable one, and none
/// at all: each reload exits 1, names why, and leaves the frontend as it
/// was.
#[test]
fn reload_refuses_an_older_or_missing_or_unreadable_binary() {
    use std::os::unix::fs::PermissionsExt;
    let _serial = serialised();
    let images = images();
    let older = images.newer("qshd-older", b"\0reload-older\0", images.a.build - 1);
    let locked = images.newer("qshd-locked", b"\0reload-locked\0", images.a.build + 1);
    let daemon = serve(&images, &labels(&[&older, &locked]), "");
    let token = [122; 16];
    let (shell, _) = served_shell(&daemon, token, "kept-122");
    let frontend = frontend_of(daemon.host);
    let built = Path::new(env!("CARGO_BIN_EXE_qshd"));

    daemon.install(&older);
    let reloaded = daemon.reload();
    assert_eq!(reloaded.code, Some(1), "{}", reloaded.output);
    assert!(reloaded.output.contains("older"), "{}", reloaded.output);
    assert_eq!(frontends_of(daemon.host), [frontend], "after the older one");

    std::fs::set_permissions(&locked.path, std::fs::Permissions::from_mode(0o000)).unwrap();
    daemon.install(&locked);
    let reloaded = daemon.reload_with(built);
    assert_eq!(reloaded.code, Some(1), "{}", reloaded.output);
    assert!(
        reloaded.output.contains("cannot open"),
        "{}",
        reloaded.output
    );
    assert_eq!(
        frontends_of(daemon.host),
        [frontend],
        "after the unreadable one"
    );

    std::fs::remove_file(&daemon.path).unwrap();
    let reloaded = daemon.reload_with(built);
    assert_eq!(reloaded.code, Some(1), "{}", reloaded.output);
    assert!(
        reloaded.output.contains("cannot open"),
        "{}",
        reloaded.output
    );
    assert_eq!(
        frontends_of(daemon.host),
        [frontend],
        "after the missing one"
    );

    let back = daemon.come_back(token);
    assert_eq!(back.same_shell("kept-122"), shell);
    back.client.close();
    daemon.finish();
}

/// Another client is attached: the user's reload is the consent to
/// disconnect it briefly. The frontend is replaced, and the client's
/// session is kept.
#[test]
fn reload_performs_a_soft_outcome() {
    let _serial = serialised();
    let images = images();
    let b = images.newer("qshd-b", b"\0reload-b\0", images.a.build + 1);
    let daemon = serve(&images, &labels(&[&b]), "");
    let token = [123; 16];
    let session = daemon.connect(token);
    let shell = session.open_shell("kept-123");
    let old = frontend_of(daemon.host);

    daemon.install(&b);
    let reloaded = daemon.reload();
    assert_eq!(
        reloaded.code,
        Some(0),
        "{}; log: {}",
        reloaded.output,
        daemon.log()
    );
    assert!(
        daemon.log().contains("(Soft { attached: 1 })"),
        "the reload disconnected the attached client; log: {}",
        daemon.log()
    );
    let next = frontend_after(daemon.host, old);
    assert_eq!(image_of(next), b.checksum);
    session.client.detach();
    let back = daemon.come_back(token);
    assert_eq!(back.same_shell("kept-123"), shell);
    back.client.close();
    daemon.finish();
}

/// B serves none of the session profiles: the retained session's client
/// could not reach it through B. A reload never does that; it refuses,
/// says how to update deliberately, and logs the outcome.
#[test]
fn reload_refuses_an_unreachable_outcome() {
    let _serial = serialised();
    let images = images();
    let b = images.newer("qshd-b", b"\0reload-b\0", images.a.build + 1);
    let daemon = serve(
        &images,
        &labels(&[&b]),
        &format!("{}=no-profiles", b.checksum),
    );
    let token = [124; 16];
    let (shell, _) = served_shell(&daemon, token, "kept-124");
    let frontend = frontend_of(daemon.host);

    daemon.install(&b);
    let reloaded = daemon.reload();
    assert_eq!(reloaded.code, Some(1), "{}", reloaded.output);
    assert!(
        reloaded.output.contains("systemctl --user restart qshd"),
        "{}",
        reloaded.output
    );
    assert!(
        daemon.log().contains("Unreachable {"),
        "the outcome is logged; log: {}",
        daemon.log()
    );
    assert_eq!(
        frontends_of(daemon.host),
        [frontend],
        "A's frontend serves on"
    );
    let back = daemon.come_back(token);
    assert_eq!(back.same_shell("kept-124"), shell);
    back.client.close();
    daemon.finish();
}

/// A daemon that has no reload socket -- here a `transport-ensure` daemon,
/// which never binds one; an older `serve` is the same -- is not touched:
/// `reload` says that it got no answer and exits 1, and the daemon serves
/// on.
#[test]
fn reload_against_a_daemon_without_the_socket_fails_and_leaves_it_running() {
    let _serial = serialised();
    let images = images();
    let daemon = start(&images, "", "");
    let token = [125; 16];
    let (shell, _) = retained_shell(&daemon, token, "kept-125");
    let frontend = frontend_of(daemon.host);

    let reloaded = reload_in(&images.a.path, daemon.home.path(), daemon.port);
    assert_eq!(reloaded.code, Some(1), "{}", reloaded.output);
    assert!(
        reloaded.output.contains(
            "the running qshd did not answer the reload: it cannot reload, or it did not \
             finish in time; check `qshd`'s log or `systemctl --user status qshd`; to restart \
             deliberately, use `systemctl --user restart qshd`"
        ),
        "{}",
        reloaded.output
    );
    assert_eq!(frontends_of(daemon.host), [frontend], "the same frontend");
    assert_eq!(status(&daemon.sock).map(|s| s.pid), Some(daemon.host));
    let back = daemon.come_back(token);
    assert_eq!(back.same_shell("kept-125"), shell);
    back.client.close();
    daemon.finish();
}
