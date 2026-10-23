//! Linux personal executable signals, real PTY scope and initial exec state.
use super::*;
use nix::libc;
use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::sync::atomic::{AtomicUsize, Ordering};

pub(super) fn qualify_borrowed_fixture() {
    let pid = std::process::id();
    assert_eq!(
        std::fs::read_link("/proc/self").unwrap().to_str().unwrap(),
        pid.to_string()
    );
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    for field in ["Pid", "Tgid"] {
        let value = status
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{field}:")))
            .unwrap();
        assert_eq!(value.trim().parse::<u32>().unwrap(), pid);
    }
    let pin = Pin::new(pid);
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe {
            libc::waitid(
                libc::P_PIDFD,
                pin.0.as_raw_fd() as u32,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT | libc::__WALL,
            )
        },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
    assert!(std::fs::read_dir("/proc/self/task").is_ok());
}

static RESCUES: AtomicUsize = AtomicUsize::new(0);

pub(super) struct Pin(OwnedFd);
impl Pin {
    pub(super) fn new(pid: u32) -> Self {
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        assert!(
            raw >= 0,
            "exact personal fixture pidfd: {}",
            std::io::Error::last_os_error()
        );
        Self(unsafe { OwnedFd::from_raw_fd(raw as i32) })
    }
    fn exited(&self) -> bool {
        let mut poll = libc::pollfd {
            fd: self.0.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            let result = unsafe { libc::poll(&mut poll, 1, 0) };
            if result >= 0 {
                return poll.revents & libc::POLLIN != 0;
            }
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EINTR)
            );
        }
    }
    fn signal(&self, signal: i32) {
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.0.as_raw_fd(),
                    signal,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            },
            0
        );
    }
    fn native(&self) -> (i32, i32) {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        loop {
            let result = unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    self.0.as_raw_fd() as u32,
                    &mut info,
                    libc::WEXITED | libc::WNOWAIT,
                )
            };
            if result == 0 {
                return (info.si_code, unsafe { info.si_status() });
            }
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EINTR)
            );
        }
    }
}

// Owns the exact wait even for the double-fork child adopted by this private
// subreaper. A rescue cannot produce a successful body receipt.
struct NativeOwner {
    pin: Pin,
    _child: Option<std::process::Child>,
    waited: bool,
}
impl NativeOwner {
    fn spawned(child: std::process::Child) -> Self {
        Self {
            pin: Pin::new(child.id()),
            _child: Some(child),
            waited: false,
        }
    }
    fn adopted(pid: u32) -> Self {
        Self {
            pin: Pin::new(pid),
            _child: None,
            waited: false,
        }
    }
    fn finish(&mut self) -> (i32, i32) {
        assert!(
            wait_for(Duration::from_secs(5), || self.pin.exited()),
            "owned daemon native completion"
        );
        let native = self.pin.native();
        super::test_borrowed_scope::wait_expected(self.pin.0.as_fd());
        self.waited = true;
        native
    }
}
impl Drop for NativeOwner {
    fn drop(&mut self) {
        if self.waited {
            return;
        }
        RESCUES.fetch_add(1, Ordering::SeqCst);
        if !self.pin.exited() {
            self.pin.signal(libc::SIGKILL);
        }
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        loop {
            let result = unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    self.pin.0.as_raw_fd() as u32,
                    &mut info,
                    libc::WEXITED,
                )
            };
            if result == 0 {
                break;
            }
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                break;
            }
        }
    }
}

fn isolated(command: &mut Command, home: &Path, probe: &Path) {
    command
        .env_clear()
        .current_dir(home)
        .env("HOME", home)
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_RUNTIME_DIR", home.join("runtime"))
        .env("HISTFILE", "/dev/null")
        .env("ENV", "/dev/null")
        .env("BASH_ENV", "/dev/null")
        .env("ZDOTDIR", home)
        .env("SHELL", probe)
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .env("TERM", "xterm-256color")
        .env("QSH_TEST_PERSONAL_HOME", home)
        .env("QSH_TEST_PERSONAL_PROBE", home.join("probe"))
        .env("QSH_TEST_PERSONAL_PIDS", home.join("pids"))
        .stdin(Stdio::null());
    for dir in ["cache", "config", "runtime"] {
        std::fs::create_dir_all(home.join(dir)).unwrap();
    }
    let output = std::fs::File::create(home.join("daemon-output")).unwrap();
    command.stdout(output.try_clone().unwrap()).stderr(output);
}

fn generated_probe(dir: &Path) -> PathBuf {
    let source = dir.join("probe.c");
    std::fs::write(&source, include_str!("../fixtures/personal_signal_probe.c")).unwrap();
    let probe = dir.join("probe-exec");
    assert!(Command::new("cc")
        .args(["-std=c11", "-Wall", "-Wextra", "-Werror"])
        .arg(&source)
        .arg("-o")
        .arg(&probe)
        .status()
        .unwrap()
        .success());
    probe
}

fn read_probe(home: &Path) -> std::collections::BTreeMap<String, i64> {
    std::fs::read_to_string(home.join("probe"))
        .unwrap()
        .split_whitespace()
        .map(|field| {
            let (key, value) = field.split_once('=').unwrap();
            (key.to_owned(), value.parse().unwrap())
        })
        .collect()
}

fn signed_client(port: u16, server_pub: [u8; 32], key: ssh_key::PrivateKey) -> StdClient {
    let events = Arc::new(Events::default());
    let login = nix::unistd::User::from_uid(nix::unistd::Uid::current())
        .unwrap()
        .unwrap()
        .name;
    let client = StdClient::connect(
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port),
        ConnectionConfig {
            required_features: transport::Features::NONE,
            features: transport::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: generate_keypair().private,
            remote_static_pub: Some(server_pub),
            auth: AuthPolicy::SshSignature,
        },
        [71; 16],
        StartKind::Cold,
        Arc::new(NoopBinder),
        events.clone(),
        Some(Arc::new(
            sshauth::sign_file::FileSigner::from_key(key)
                .unwrap()
                .with_login(login),
        )),
    );
    assert!(wait_for(Duration::from_secs(5), || events
        .records
        .lock()
        .unwrap()
        .live));
    client
}

fn open_shell(client: &StdClient) {
    client
        .send_bytes(
            CONTROL_STREAM,
            encode_client(&ClientRecord::Open(OpenRequest {
                stream: FIRST_CHANNEL_STREAM,
                kind: ChannelKind::Shell,
                cols: 80,
                rows: 24,
                screen: false,
                command: Vec::new(),
            })),
        )
        .expect("personal shell Open admitted");
}

fn wait_pids(home: &Path) -> (u32, u32) {
    let path = home.join("pids");
    assert!(
        wait_for(Duration::from_secs(5), || path.exists()),
        "probe shell spawned its same-session job"
    );
    let text = std::fs::read_to_string(path).unwrap();
    let pids: Vec<u32> = text
        .split_whitespace()
        .map(|pid| pid.parse().unwrap())
        .collect();
    assert_eq!(pids.len(), 2);
    (pids[0], pids[1])
}

struct ReleaseGate {
    file: std::fs::File,
    released: bool,
}
impl ReleaseGate {
    fn release(&mut self) {
        if !self.released {
            self.file.write_all(b"release\n").unwrap();
            self.released = true;
        }
    }
}
impl Drop for ReleaseGate {
    fn drop(&mut self) {
        // One nonblocking release attempt precedes failed-run actor stop.
        if !self.released {
            let _ = self.file.write(b"release\n");
        }
    }
}

fn live_case(bin: &Path, probe: &Path, home: &Path, mode: &str, signal: i32, outsider: &Pin) {
    std::fs::create_dir(home).unwrap();
    std::fs::set_permissions(home, std::fs::Permissions::from_mode(0o700)).unwrap();
    let client_key = generate_keypair();
    let udp = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
    let port = udp.local_addr().unwrap().port();
    let mut command = Command::new(bin);
    isolated(&mut command, home, probe);
    let held_case = matches!(mode, "resume" | "ensure") && signal == libc::SIGTERM;
    let early_gate = if held_case {
        let path = home.join("close-release");
        nix::unistd::mkfifo(
            &path,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&path)
            .unwrap();
        Some(ReleaseGate {
            file,
            released: false,
        })
    } else {
        None
    };
    if held_case {
        command
            .env("QSH_TEST_PERSONAL_RELEASE", home.join("close-release"))
            .env("QSH_TEST_PERSONAL_HELD", home.join("close-held"));
    }
    let socket = home.join("cache/qsh/control.sock");
    let (mut owner, server_pub, signed) = match mode {
        "serve" => {
            drop(udp);
            let key = ssh_key::PrivateKey::random(
                &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                ssh_key::Algorithm::Ed25519,
            )
            .unwrap();
            let authorized = home.join("authorized_keys");
            std::fs::write(&authorized, key.public_key().to_openssh().unwrap()).unwrap();
            let host = home.join("host-key");
            let server = qshd::load_or_create_transport_key(&host).unwrap();
            command
                .arg("serve")
                .args(["--port", &port.to_string(), "--authorized-keys"])
                .arg(authorized)
                .arg("--host-key")
                .arg(host);
            (
                NativeOwner::spawned(command.spawn().unwrap()),
                server.public,
                Some(key),
            )
        }
        "ensure" => {
            drop(udp);
            command.args([
                "transport-ensure",
                "--name",
                "qshd-test-signal",
                "--port",
                &port.to_string(),
                "--client-pubkey",
                &BASE64.encode(client_key.public),
            ]);
            assert!(
                command.status().unwrap().success(),
                "real double-fork launcher succeeded"
            );
            let mut answer = None;
            assert!(wait_for(Duration::from_secs(5), || {
                answer = status(&socket);
                answer.is_some()
            }));
            let answer = answer.unwrap();
            let owner = NativeOwner::adopted(answer.pid);
            let task = std::fs::read_to_string(format!("/proc/{}/status", answer.pid)).unwrap();
            assert!(task.lines().any(|line| line
                .strip_prefix("PPid:")
                .is_some_and(|parent| parent.trim() == std::process::id().to_string())));
            assert_eq!(status(&socket).unwrap().pid, answer.pid);
            let key = qshd::load_or_create_transport_key(
                &home.join("cache/qsh/transport_server_key.bin"),
            )
            .unwrap();
            (owner, key.public, None)
        }
        "resume" => {
            let cache = home.join("cache/qsh");
            std::fs::create_dir_all(&cache).unwrap();
            let server =
                qshd::load_or_create_transport_key(&cache.join("transport_server_key.bin"))
                    .unwrap();
            let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
            std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
            let staged = home.join("staged-qshd");
            copy_executable(bin, &staged);
            let handover = qshd::handover::Handover {
                handover_version: 1,
                binary_path: home.join("resumed-qshd"),
                staged_path: staged.clone(),
                udp_fd: udp.as_raw_fd(),
                control_fd: listener.as_raw_fd(),
                control_path: socket.clone(),
                cache_dir: cache,
                port,
                ports: vec![port],
                name: "qshd-test-signal".into(),
                allowlist: qshd::handover::encode_allowlist(&[client_key.public]),
            };
            let handover_fd = qshd::handover::write_memfd(&handover).unwrap();
            let fds = [
                udp.as_raw_fd(),
                listener.as_raw_fd(),
                handover_fd.as_raw_fd(),
            ];
            for fd in fds {
                qshd::handover::set_cloexec(fd, false).unwrap();
            }
            command = Command::new(staged);
            isolated(&mut command, home, probe);
            if held_case {
                command
                    .env("QSH_TEST_PERSONAL_RELEASE", home.join("close-release"))
                    .env("QSH_TEST_PERSONAL_HELD", home.join("close-held"));
            }
            command
                .arg("transport-resume")
                .env(HANDOVER_FD_ENV, handover_fd.as_raw_fd().to_string());
            let child = command.spawn();
            for fd in fds {
                qshd::handover::set_cloexec(fd, true).unwrap();
            }
            let owner = NativeOwner::spawned(child.unwrap());
            drop(udp);
            drop(listener);
            drop(handover_fd);
            (owner, server.public, None)
        }
        _ => unreachable!(),
    };
    // This guard drops before the actor owner: release precedes failed-run
    // exact stop/wait cleanup if an assertion unwinds while the hook is held.
    let mut release_gate = early_gate;
    // A completed signed/allowlisted handshake is readiness after signal
    // registration, not the executable's earlier startup banner.
    let client = match signed {
        Some(key) => signed_client(port, server_pub, key),
        None => connect(home, port, server_pub, client_key.private, [72; 16]).0,
    };
    open_shell(&client);
    let (leader_pid, job_pid) = wait_pids(home);
    let leader = Pin::new(leader_pid);
    let job = Pin::new(job_pid);
    let report = read_probe(home);
    assert_eq!(report["pid"], leader_pid as i64);
    for key in ["term_blocked", "int_blocked", "inherited_fds"] {
        assert_eq!(report[key], 0, "initial exec {key}");
    }
    for key in ["term_default", "int_default", "home_owned"] {
        assert_eq!(report[key], 1, "initial exec {key}");
    }
    assert_eq!(
        unsafe { libc::getsid(leader_pid as i32) },
        leader_pid as i32
    );
    assert_eq!(unsafe { libc::getsid(job_pid as i32) }, leader_pid as i32);
    assert!(!leader.exited() && !job.exited() && !owner.pin.exited());
    let stop_ack = mode == "ensure" && held_case;
    if stop_ack {
        let reply = client_request(&socket, &ControlRequest::Stop).unwrap();
        let ControlReply::Answered(line) = reply else {
            panic!("admitted STOP requires its ACK");
        };
        let ack: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(ack["stopping"], true);
        assert!(ack.get("stopped").is_none());
        assert!(
            wait_for(Duration::from_secs(3), || home.join("close-held").exists()),
            "STOP cleanup physically entered the held hook before TERM"
        );
        assert!(
            !owner.pin.exited() && !leader.exited() && !job.exited(),
            "accepted STOP still owns its held cleanup when TERM arrives"
        );
    }
    owner.pin.signal(signal);
    if let Some(gate) = release_gate.as_mut() {
        assert!(
            wait_for(Duration::from_secs(3), || home.join("close-held").exists()),
            "real HUP cleanup hook entered"
        );
        assert!(
            !owner.pin.exited() && !leader.exited() && !job.exited(),
            "scope drain is physically held"
        );
        owner.pin.signal(libc::SIGINT);
        owner.pin.signal(libc::SIGTERM);
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !owner.pin.exited(),
            "repeated signals cannot replace joined drain with signal death"
        );
        gate.release();
    }
    let native = owner.finish();
    assert!(
        leader.exited() && job.exited(),
        "joined daemon must settle its real PTY scope"
    );
    // The descriptor-holding job is no longer the daemon's waitable leader.
    // Its exact native exit is consumed by this exclusively waitable subreaper.
    let job_native = job.native();
    super::test_borrowed_scope::wait_expected(job.0.as_fd());
    client.close();
    assert_eq!(
        native,
        (libc::CLD_EXITED, 0),
        "{mode} signal {signal} requires joined native success"
    );
    assert!(!outsider.exited(), "outside fixture process survives");
    let rebound = UdpSocket::bind(("127.0.0.1", port)).unwrap();
    drop(rebound);
    let receipt = format!("mode={mode} signal={signal} daemon={native:?} leader={leader_pid} job={job_pid} job_native={job_native:?} probe={report:?} held_repeat={} stop_ack={} scope_exited=1 rebind=1 outsider_alive=1\n", usize::from(held_case), usize::from(stop_ack));
    let path = PathBuf::from(std::env::var_os("QSH_TEST_PERSONAL_DIAGNOSTIC").unwrap())
        .with_extension("cases");
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap()
        .write_all(receipt.as_bytes())
        .unwrap();
}

#[test]
fn personal_unix_signals_join_real_shell_scopes() {
    let diagnostic_owner = std::env::var_os("QSH_TEST_BORROWED_SCOPE_MODE")
        .is_none()
        .then(|| tempfile::tempdir().unwrap());
    if let Some(dir) = diagnostic_owner.as_ref() {
        std::env::set_var("QSH_TEST_PERSONAL_DIAGNOSTIC", dir.path().join("phase"));
    }
    let result = super::test_borrowed_scope::run_exact(
        "personal_signals::personal_unix_signals_join_real_shell_scopes",
        12,
        || {
            let previous = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                let path = std::env::var_os("QSH_TEST_PERSONAL_DIAGNOSTIC").unwrap();
                let prior = std::fs::read_to_string(&path).unwrap_or_default();
                let detail = format!("{info}");
                let _ = std::fs::write(
                    path,
                    format!(
                        "{prior} panic={}",
                        detail.chars().take(2048).collect::<String>()
                    ),
                );
                previous(info);
            }));
            let bins = stripped_qshd();
            let fixture = tempfile::tempdir().unwrap();
            let probe = generated_probe(fixture.path());
            let mut outsider = Command::new("/bin/sleep").arg("60").spawn().unwrap();
            let outsider_pin = Pin::new(outsider.id());
            let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                for mode in ["serve", "ensure", "resume"] {
                    for signal in [libc::SIGTERM, libc::SIGINT] {
                        std::fs::write(
                            std::env::var_os("QSH_TEST_PERSONAL_DIAGNOSTIC").unwrap(),
                            format!("mode={mode} signal={signal}"),
                        )
                        .unwrap();
                        live_case(
                            &bins.bin,
                            &probe,
                            &fixture.path().join(format!("{mode}-{signal}")),
                            mode,
                            signal,
                            &outsider_pin,
                        );
                    }
                }
            }));
            outsider_pin.signal(libc::SIGKILL);
            outsider.wait().unwrap();
            assert_eq!(
                RESCUES.load(Ordering::SeqCst),
                0,
                "native fixture needed no rescue"
            );
            if let Err(cause) = run {
                std::panic::resume_unwind(cause);
            }
        },
    );
    if !result.body_success {
        eprintln!(
            "personal fixture phase: {}",
            std::fs::read_to_string(std::env::var_os("QSH_TEST_PERSONAL_DIAGNOSTIC").unwrap())
                .unwrap_or_default()
        );
    }
    let receipts = PathBuf::from(std::env::var_os("QSH_TEST_PERSONAL_DIAGNOSTIC").unwrap())
        .with_extension("cases");
    let mut bytes = String::new();
    if let Ok(file) = std::fs::File::open(receipts) {
        file.take(16_384).read_to_string(&mut bytes).unwrap();
    }
    eprintln!("{bytes}native scope outcome {result:?}");
    result.assert_clean(12);
}

#[test]
fn personal_exec_probe_observes_a_real_inherited_mask_and_ignored_signal() {
    let dir = tempfile::tempdir().unwrap();
    let probe = generated_probe(dir.path());
    let home = dir.path().join("home");
    std::fs::create_dir(&home).unwrap();
    let sentinel = home.join("owned-descriptor");
    std::fs::write(&sentinel, b"owned inherited descriptor fixture\n").unwrap();
    let mut command = Command::new(&probe);
    isolated(&mut command, &home, &probe);
    command
        .arg("--inherited-control")
        .env("QSH_TEST_PERSONAL_PROBE_ONLY", "1")
        .env("QSH_TEST_PERSONAL_SENTINEL", sentinel);
    assert!(command.status().unwrap().success());
    let actual = read_probe(&home);
    assert_eq!(actual["term_blocked"], 1);
    assert_eq!(actual["int_blocked"], 0);
    assert_eq!(actual["term_default"], 1);
    assert_eq!(actual["int_default"], 0);
    // This direct control bypasses the daemon's PTY descriptor closure. Its
    // setup child deliberately inherits one exact file alongside harness fds.
    assert_eq!(actual["sentinel_inherited"], 1);
    assert!(actual["inherited_fds"] >= 1);
    eprintln!("inherited signal/owned-descriptor control: {actual:?}");
}

#[test]
fn personal_signal_registration_failure_never_admits_a_manager() {
    let result = super::test_borrowed_scope::run_exact(
        "personal_signals::personal_signal_registration_failure_never_admits_a_manager",
        2,
        || {
            let bins = stripped_qshd();
            let dir = tempfile::tempdir().unwrap();
            let probe = generated_probe(dir.path());
            for signal in [libc::SIGTERM, libc::SIGINT] {
                let home = dir.path().join(format!("register-{signal}"));
                std::fs::create_dir(&home).unwrap();
                let port = free_udp_port();
                let keys = home.join("authorized_keys");
                std::fs::write(&keys, "").unwrap();
                let mut command = Command::new(&probe);
                isolated(&mut command, &home, &probe);
                command
                    .arg("--deny-signal")
                    .arg(signal.to_string())
                    .arg(&bins.bin)
                    .args(["serve", "--port", &port.to_string(), "--authorized-keys"])
                    .arg(keys)
                    .arg("--host-key")
                    .arg(home.join("host-key"));
                let mut owner = NativeOwner::spawned(command.spawn().unwrap());
                let native = owner.finish();
                assert_eq!(native.0, libc::CLD_EXITED);
                assert_ne!(native.1, 0, "registration failure is startup failure");
                let output = std::fs::read_to_string(home.join("daemon-output")).unwrap();
                let name = if signal == libc::SIGTERM {
                    "SIGTERM"
                } else {
                    "SIGINT"
                };
                assert!(
                    output.contains(&format!("registering personal daemon {name}")),
                    "actual denied signal registration must be visible: {output}"
                );
                let rebound = UdpSocket::bind(("127.0.0.1", port)).unwrap();
                drop(rebound);
                eprintln!("personal registration signal={signal} native={native:?} rebind=1");
            }
            assert_eq!(RESCUES.load(Ordering::SeqCst), 0);
        },
    );
    eprintln!("native registration outcome {result:?}");
    result.assert_clean(2);
}
