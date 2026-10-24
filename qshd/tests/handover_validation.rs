//! Raw descriptor cases run in a fresh child so malformed inputs cannot damage
//! the test runner's descriptors or race its environment and descriptor reuse.
use std::fs::{self, File};
use std::io::{Seek, SeekFrom, Write};
use std::net::{TcpListener, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
use std::process::Command;

use qshd::handover::{self, Handover, HANDOVER_FD_ENV};

const CASE: &str = "QSHD_HANDOVER_VALIDATION_CASE";

#[test]
fn malformed_handover_is_refused_before_ownership_or_mutation() {
    if let Ok(case) = std::env::var(CASE) {
        child(&case);
        println!("handover case completed: {case}");
        return;
    }
    let mut failures = Vec::new();
    let mut count = 0;
    for case in [
        "stdio",
        "stderr",
        "negative",
        "nonnumeric",
        "overflow",
        "closed-state",
        "pipe-state",
        "named-state",
        "duplicate",
        "dup-socket",
        "state-control-alias",
        "closed-control",
        "negative-udp",
        "state-alias",
        "closed-udp",
        "stdio-control",
        "file-udp",
        "tcp-udp",
        "tcp-control",
        "unix-datagram-udp",
        "stream-control",
        "datagram-control",
        "port",
        "control-path",
        "control-file",
        "stage-symlink",
        "destination-symlink",
        "same-destination",
        "stage-inode",
        "stage-name",
        "destination-directory",
        "allowlist",
        "success",
        "success-nonstandard-name",
    ] {
        count += 1;
        let home = tempfile::tempdir().unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "malformed_handover_is_refused_before_ownership_or_mutation",
                "--nocapture",
            ])
            .env(CASE, case)
            .env("HOME", home.path())
            .env("XDG_CONFIG_HOME", home.path().join("config"))
            .env("XDG_CACHE_HOME", home.path().join("cache"))
            .env("HISTFILE", "/dev/null")
            .output()
            .unwrap();
        if !output.status.success()
            || !String::from_utf8_lossy(&output.stdout)
                .contains(&format!("handover case completed: {case}"))
        {
            failures.push(format!(
                "{case}: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    println!("validated {count} isolated handover cases");
}

fn take_handover() -> anyhow::Result<Option<handover::PreparedHandover>> {
    // SAFETY: fixtures relinquish the offered handles with into_raw_fd. Each
    // case is isolated; no other thread opens/closes them or holds a Rust owner.
    // Invalid/stdio numbers are rejected before they can transfer ownership.
    unsafe { handover::take_from_env() }
}

fn child(case: &str) {
    if [
        "stdio",
        "stderr",
        "closed-state",
        "negative",
        "nonnumeric",
        "overflow",
    ]
    .contains(&case)
    {
        let value = match case {
            "stdio" => "0",
            "stderr" => "2",
            "closed-state" => "1000000",
            "negative" => "-1",
            "nonnumeric" => "not-a-number",
            _ => "2147483648",
        };
        std::env::set_var(HANDOVER_FD_ENV, value);
        assert!(take_handover().is_err());
        assert!(std::env::var_os(HANDOVER_FD_ENV).is_none());
        if case == "stdio" || case == "stderr" {
            assert!(handover::is_cloexec(value.parse().unwrap()).is_ok());
        }
        return;
    }
    if case == "pipe-state" {
        let (read, _write) = nix::unistd::pipe().unwrap();
        let fd = read.into_raw_fd();
        std::env::set_var(HANDOVER_FD_ENV, fd.to_string());
        assert!(take_handover().is_err());
        assert!(
            handover::is_cloexec(fd).is_ok(),
            "unaccepted pipe was closed"
        );
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let binary = dir.path().join(if case == "success-nonstandard-name" {
        ".qshd-update-custom-name"
    } else {
        "custom-daemon-name"
    });
    fs::write(&binary, b"original destination sentinel").unwrap();
    let staged = dir
        .path()
        .join(format!(".qshd-update-{}-1234", std::process::id()));
    fs::hard_link(std::env::current_exe().unwrap(), &staged).unwrap();
    let control_path = dir.path().join("control.sock");
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = udp.local_addr().unwrap().port();
    let listener = qshd::control::bind_private(&control_path).unwrap();
    // Relinquish fixtures before crossing the production adoption boundary.
    // Invalid cases remain open for explicit assertions or kernel cleanup on
    // child exit; no second Rust owner can ever double-close an accepted fd.
    let udp_fd = udp.into_raw_fd();
    let control_fd = listener.into_raw_fd();
    handover::set_cloexec(udp_fd, false).unwrap();
    handover::set_cloexec(control_fd, false).unwrap();
    let mut h = Handover {
        handover_version: qshd::state::HANDOVER_VERSION,
        binary_path: binary.clone(),
        staged_path: staged.clone(),
        udp_fd,
        control_fd,
        control_path: control_path.clone(),
        cache_dir: dir.path().to_owned(),
        port,
        ports: vec![port],
        name: "main".into(),
        allowlist: vec![],
    };
    let state = tempfile::tempfile().unwrap();
    let state_fd = state.into_raw_fd();
    match case {
        "named-state" | "success" | "success-nonstandard-name" => {}
        "dup-socket" => h.control_fd = nix::unistd::dup(udp_fd).unwrap(),
        "state-control-alias" => h.control_fd = state_fd,
        "closed-control" => h.control_fd = 1_000_000,
        "negative-udp" => h.udp_fd = -1,
        "control-file" => {
            fs::remove_file(&control_path).unwrap();
            fs::write(&control_path, b"control sentinel").unwrap();
        }
        "stage-symlink" => {
            fs::remove_file(&staged).unwrap();
            std::os::unix::fs::symlink(std::env::current_exe().unwrap(), &staged).unwrap();
        }
        "destination-symlink" => {
            fs::remove_file(&binary).unwrap();
            fs::write(
                dir.path().join("sentinel"),
                b"original destination sentinel",
            )
            .unwrap();
            std::os::unix::fs::symlink(dir.path().join("sentinel"), &binary).unwrap();
        }
        "same-destination" => h.binary_path = staged.clone(),
        "duplicate" => h.control_fd = udp_fd,
        "state-alias" => h.udp_fd = state_fd,
        "closed-udp" => h.udp_fd = 1_000_000,
        "stdio-control" => h.control_fd = 2,
        "file-udp" => h.udp_fd = File::open(&binary).unwrap().into_raw_fd(),
        "tcp-control" => h.control_fd = TcpListener::bind("127.0.0.1:0").unwrap().into_raw_fd(),
        "tcp-udp" => h.udp_fd = TcpListener::bind("127.0.0.1:0").unwrap().into_raw_fd(),
        "unix-datagram-udp" => h.udp_fd = UnixDatagram::unbound().unwrap().into_raw_fd(),
        "stream-control" => {
            let (one, _two) = UnixStream::pair().unwrap();
            h.control_fd = one.into_raw_fd();
        }
        "datagram-control" => h.control_fd = UnixDatagram::unbound().unwrap().into_raw_fd(),
        "port" => h.port = if port == 1 { 2 } else { 1 },
        "control-path" => {
            h.control_path = dir.path().join("other.sock");
            let _other = UnixListener::bind(&h.control_path).unwrap();
        }
        "stage-inode" => {
            fs::remove_file(&staged).unwrap();
            fs::write(&staged, b"unrelated stage sentinel").unwrap();
        }
        "stage-name" => {
            let other = dir.path().join("unrelated-stage");
            fs::rename(&staged, &other).unwrap();
            h.staged_path = other;
        }
        "destination-directory" => {
            fs::create_dir(dir.path().join("other")).unwrap();
            h.binary_path = dir.path().join("other/destination");
            fs::write(&h.binary_path, b"other sentinel").unwrap();
        }
        "allowlist" => h.allowlist = vec!["malformed".into()],
        _ => panic!("unknown case {case}"),
    }
    let original_flags = handover::is_cloexec(udp_fd).unwrap();
    // The test is the only owner of this raw state fd until handing it off.
    let mut file = unsafe { File::from_raw_fd(state_fd) };
    file.write_all(&serde_json::to_vec(&h).unwrap()).unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    if case == "named-state" {
        let named = dir.path().join("named-state");
        fs::write(&named, serde_json::to_vec(&h).unwrap()).unwrap();
        drop(file);
        file = File::open(named).unwrap();
    }
    let fd = file.into_raw_fd();
    std::env::set_var(HANDOVER_FD_ENV, fd.to_string());
    if case.starts_with("success") {
        let incoming = take_handover().unwrap().expect("validated handover");
        assert!(handover::is_cloexec(udp_fd).unwrap());
        assert!(handover::is_cloexec(control_fd).unwrap());
        assert!(
            handover::is_cloexec(fd).is_err(),
            "state file must close after preparation"
        );
        drop(incoming);
        assert!(
            handover::is_cloexec(udp_fd).is_err(),
            "accepted UDP fd must close with its owner"
        );
        assert!(
            handover::is_cloexec(control_fd).is_err(),
            "accepted control fd must close with its owner"
        );
        return;
    }
    assert!(
        take_handover().is_err(),
        "malformed {case} handover was accepted"
    );
    assert!(std::env::var_os(HANDOVER_FD_ENV).is_none());
    assert!(
        handover::is_cloexec(udp_fd).is_ok(),
        "unaccepted UDP descriptor was closed"
    );
    assert_eq!(handover::is_cloexec(udp_fd).unwrap(), original_flags);
    assert_eq!(fs::read(&binary).unwrap(), b"original destination sentinel");
    assert!(control_path.exists(), "control publication was unlinked");
}

#[test]
fn invalid_socket_or_allowlist_cannot_rename_or_unlink_during_resume() {
    for bad_socket in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("custom-daemon-name");
        fs::write(&binary, b"destination sentinel").unwrap();
        // This deliberately unrelated stage must never be renamed. The old
        // resume renames first, before discovering an invalid socket/allowlist.
        let staged = dir.path().join("unrelated-stage");
        fs::hard_link(env!("CARGO_BIN_EXE_qshd"), &staged).unwrap();
        let control_path = dir.path().join("control.sock");
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let listener = qshd::control::bind_private(&control_path).unwrap();
        let h = Handover {
            handover_version: qshd::state::HANDOVER_VERSION,
            binary_path: binary.clone(),
            staged_path: staged.clone(),
            udp_fd: if bad_socket {
                1_000_000
            } else {
                udp.as_raw_fd()
            },
            control_fd: listener.as_raw_fd(),
            control_path: control_path.clone(),
            cache_dir: dir.path().to_owned(),
            port: udp.local_addr().unwrap().port(),
            ports: vec![],
            name: "main".into(),
            allowlist: if bad_socket {
                vec![]
            } else {
                vec!["invalid".into()]
            },
        };
        let state = handover::write_memfd(&h).unwrap();
        for fd in [state.as_raw_fd(), udp.as_raw_fd(), listener.as_raw_fd()] {
            handover::set_cloexec(fd, false).unwrap();
        }
        let output = Command::new(&staged)
            .arg("transport-resume")
            .env(HANDOVER_FD_ENV, state.as_raw_fd().to_string())
            .env("HOME", dir.path())
            .env("XDG_CONFIG_HOME", dir.path().join("config"))
            .env("XDG_CACHE_HOME", dir.path().join("cache"))
            .env("HISTFILE", "/dev/null")
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            fs::read(&binary).unwrap() == b"destination sentinel",
            "refusal renamed the destination"
        );
        assert!(
            control_path.exists(),
            "refusal unlinked an unaccepted publication"
        );
        assert!(staged.exists(), "refusal moved an unrelated executable");
        assert!(
            !dir.path().join("qshd.log").exists(),
            "refusal opened the unvalidated log directory"
        );
    }
}
