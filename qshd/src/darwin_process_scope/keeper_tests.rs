use super::keeper::*;
#[test]
fn keeper_control_partial_frame_and_sequence() {
    let instance = [17; 16];
    let frame = Frame {
        operation: Operation::AppWait,
        fields: [37, 0, 0, 0],
    };
    let bytes = encode(instance, 1, frame);
    let mut decoder = Decoder::new(instance);
    for byte in &bytes[..71] {
        assert_eq!(decoder.feed(&[*byte]), Ok(None));
    }
    assert_eq!(decoder.feed(&bytes[71..]), Ok(Some(frame)));
    assert_eq!(decoder.feed(&bytes), Err(ProtocolError));
    assert_eq!(
        decoder.feed(&encode(instance, 2, frame)),
        Err(ProtocolError)
    );
}

#[test]
fn keeper_control_rejects_unbound_and_malformed_authority() {
    let instance = [17; 16];
    let frame = Frame {
        operation: Operation::Ready,
        fields: [12, 99, 3, 10],
    };
    let original = encode(instance, 1, frame);
    for offset in [0, 8, 9, 10, 12, 16, 39] {
        let mut bytes = original;
        bytes[offset] ^= 128;
        let mut decoder = Decoder::new(instance);
        assert_eq!(decoder.feed(&bytes), Err(ProtocolError), "offset {offset}");
        assert_eq!(decoder.feed(&original), Err(ProtocolError));
    }
    assert_eq!(Decoder::new(instance).feed(&[0; 73]), Err(ProtocolError));
    assert_eq!(
        Decoder::new(instance).feed(&encode(instance, 0, frame)),
        Err(ProtocolError)
    );
}

#[test]
fn keeper_control_all_operations_remain_source_bound() {
    let instance = [29; 16];
    let mut decoder = Decoder::new(instance);
    for (i, operation) in [
        Operation::Ready,
        Operation::Admit,
        Operation::AppStarted,
        Operation::AppWait,
        Operation::Stop,
        Operation::Drained,
        Operation::Exit,
        Operation::Refused,
        Operation::Foreground,
        Operation::ForegroundReady,
        Operation::KeeperReady,
        Operation::KeeperCreated,
        Operation::KeeperWait,
        Operation::BrokerMoved,
        Operation::AppFailed,
        Operation::KeeperSpawned,
        Operation::BrokerParent,
        Operation::KeeperTerminal,
    ]
    .into_iter()
    .enumerate()
    {
        let frame = Frame {
            operation,
            fields: [i as i64, 37, -1, 0],
        };
        assert_eq!(
            decoder.feed(&encode(instance, i as u64 + 1, frame)),
            Ok(Some(frame))
        );
    }
    assert_eq!(decoder.remaining(), 72);
}

#[test]
fn keeper_created_failure_retains_owner_before_refusal() {
    use super::keeper_pty::{Created, Master, Startup};
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    };
    use transport::channel_open::{CleanupAuthority, CleanupStatus, OpenCustody, SpawnCleanup};
    use transport::channel_server::{ChannelWait, ChildStatus};
    struct Wait {
        allow: Arc<AtomicBool>,
        drops: Arc<AtomicUsize>,
    }
    impl Drop for Wait {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }
    impl ChannelWait for Wait {
        fn poll_exit(&mut self) -> ChildStatus {
            ChildStatus::Running
        }
        fn kill(&mut self) {}
        fn wait(self: Box<Self>) -> i32 {
            panic!("startup refusal must retain the cleanup owner")
        }
        fn cleanup_uninstalled(&mut self, authority: &CleanupAuthority<'_>) -> CleanupStatus {
            if self.allow.load(Ordering::SeqCst) {
                authority.reaped()
            } else {
                CleanupStatus::Unknown
            }
        }
    }
    for startup in [
        Startup::Pending,
        Startup::Failed("injected watch refusal".into()),
        Startup::Ready,
    ] {
        let allow = Arc::new(AtomicBool::new(false));
        let drops = Arc::new(AtomicUsize::new(0));
        let master = Master::new(tempfile::tempfile().unwrap());
        let custody = OpenCustody::new();
        let created = Created::new(
            Box::new(master),
            Box::new(Wait {
                allow: allow.clone(),
                drops: drops.clone(),
            }),
            startup,
            &custody,
            Box::new(transport::shell_server::NoScreen),
        );
        let outcome = created.finish();
        let failure = match outcome {
            Err(failure) => failure,
            Ok(channel) => {
                drop(channel);
                custody.failure("injected post-install cancellation".into())
            }
        };
        assert_eq!(
            drops.load(Ordering::SeqCst),
            0,
            "created child owner was dropped before registration"
        );
        let SpawnCleanup::Pending(ticket) = failure.cleanup else {
            panic!("created actor misclassified as no-child");
        };
        assert!(matches!(ticket.cleanup(), CleanupStatus::Unknown));
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        allow.store(true, Ordering::SeqCst);
        assert!(matches!(ticket.cleanup(), CleanupStatus::Confirmed(_)));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn keeper_completion_reports_application_not_reservation_status() {
    use transport::channel_server::ChildStatus;
    let complete = Completion {
        app_status: Some(37),
        session_wait: Some(0),
        broker_terminal: true,
        final_census: true,
        drained: true,
    };
    assert!(matches!(
        complete.status(),
        ChildStatus::Reaped { code: Some(37) }
    ));
    for missing in 0..5 {
        let mut proof = Completion {
            app_status: Some(37),
            session_wait: Some(0),
            broker_terminal: true,
            final_census: true,
            drained: true,
        };
        match missing {
            0 => proof.app_status = None,
            1 => proof.session_wait = None,
            2 => proof.broker_terminal = false,
            3 => proof.final_census = false,
            _ => proof.drained = false,
        }
        assert!(
            matches!(proof.status(), ChildStatus::Running),
            "missing receipt {missing} qualified cleanup"
        );
    }
}

#[test]
fn keeper_launch_is_bounded_and_exactly_bound_to_instance() {
    use super::keeper_helper::Launch;
    let instance = [31; 16];
    let launch = Launch {
        argv: vec![
            "/bin/sh".into(),
            "-c".into(),
            "exit 37".into(),
            String::new(),
        ],
        environment: vec![("TERM".into(), "xterm-256color".into())],
    };
    let bytes = launch.encode(instance).unwrap();
    assert_eq!(Launch::decode(&bytes, instance), Ok(launch));
    for offset in [0, 8, 12, 28] {
        let mut bad = bytes.clone();
        bad[offset] ^= 128;
        assert!(Launch::decode(&bad, instance).is_err(), "offset {offset}");
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(Launch::decode(&extra, instance).is_err());
    assert!(Launch {
        argv: vec![String::new()],
        environment: vec![]
    }
    .encode(instance)
    .is_err());
    assert!(Launch {
        argv: vec!["program\0suffix".into()],
        environment: vec![]
    }
    .encode(instance)
    .is_err());
    assert!(Launch {
        argv: vec!["x".repeat(4097)],
        environment: vec![]
    }
    .encode(instance)
    .is_err());
    assert!(Launch {
        argv: vec!["program".into()],
        environment: vec![("BAD=NAME".into(), "value".into())]
    }
    .encode(instance)
    .is_err());
    assert!(Launch {
        argv: vec!["program".into()],
        environment: vec![("NAME".into(), "x".repeat(4097))]
    }
    .encode(instance)
    .is_err());
    let limit = Launch {
        argv: vec!["x".repeat(4096)],
        environment: vec![],
    };
    assert_eq!(
        Launch::decode(&limit.encode(instance).unwrap(), instance),
        Ok(limit)
    );
}

#[test]
fn keeper_entry_arguments_never_supply_descriptor_or_parent_authority_alone() {
    use super::keeper_helper::{EntryArgs, ENTRY};
    use std::ffi::OsString;
    let args: Vec<OsString> = [ENTRY, "123", "4", "5", "11111111111111111111111111111111"]
        .iter()
        .map(OsString::from)
        .collect();
    let parsed = EntryArgs::parse(&args).unwrap();
    assert_eq!(
        (parsed.parent, parsed.session_fd, parsed.broker_fd),
        (123, 4, 5)
    );
    for (index, value) in [
        (0, "transport-resume"),
        (1, "0"),
        (2, "2"),
        (3, "4"),
        (4, "11"),
        (4, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"),
    ] {
        let mut bad = args.clone();
        bad[index] = value.into();
        assert!(EntryArgs::parse(&bad).is_err());
    }
    assert!(EntryArgs::parse(&args[..4]).is_err());
    // Parsing describes a requested capability; it never opens a descriptor,
    // admits an application or performs a native parent-identity query.
}

#[test]
fn keeper_inherited_channel_partial_write_and_eof_are_not_completion() {
    use super::keeper_helper::Channel;
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    let instance = [41; 16];
    let (left, mut peer) = UnixStream::pair().unwrap();
    let mut bootstrap = Channel::new(left, instance).unwrap();
    let launch = super::keeper_helper::Launch {
        argv: vec!["/bin/sh".into()],
        environment: vec![],
    }
    .encode(instance)
    .unwrap();
    let mut at = 0;
    assert!(bootstrap.bootstrap(&launch, &mut at).unwrap());
    assert_eq!(at, launch.len());
    let mut observed = vec![0; launch.len()];
    std::io::Read::read_exact(&mut peer, &mut observed).unwrap();
    assert_eq!(observed, launch);
    let (left, mut right) = UnixStream::pair().unwrap();
    let mut receiver = Channel::new(left, instance).unwrap();
    let frame = Frame {
        operation: Operation::AppWait,
        fields: [37, 0, 0, 0],
    };
    let bytes = encode(instance, 1, frame);
    right.write_all(&bytes[..7]).unwrap();
    assert_eq!(receiver.receive().unwrap(), None);
    right.write_all(&bytes[7..]).unwrap();
    assert_eq!(receiver.receive().unwrap(), Some(frame));
    drop(right);
    assert_eq!(
        receiver.receive().unwrap_err().kind(),
        std::io::ErrorKind::UnexpectedEof
    );
    let (left, right) = UnixStream::pair().unwrap();
    let mut sender = Channel::new(left, instance).unwrap();
    let mut receiver = Channel::new(right, instance).unwrap();
    sender.queue(frame).unwrap();
    assert_eq!(
        sender.queue(frame).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert!(sender.flush().unwrap());
    assert_eq!(receiver.receive().unwrap(), Some(frame));
    sender.queue(frame).unwrap();
    assert!(sender.flush().unwrap());
    assert_eq!(receiver.receive().unwrap(), Some(frame));
}

#[test]
fn keeper_closed_stdio_preserves_exec_error_handshake() {
    use super::keeper_pty::StandardReservations;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    const CHILD: &str = "QSHD_KEEPER_STDIO_UNIT_CHILD";
    if let Some(record) = std::env::var_os(CHILD) {
        let mut result = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(record)
            .unwrap();
        let null = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .unwrap();
        let raw = null.as_raw_fd();
        assert!(raw >= 3);
        for fd in 0..3 {
            assert_eq!(unsafe { nix::libc::close(fd) }, 0);
        }
        let reservations = StandardReservations::acquire().unwrap();
        if !(0..3).all(|fd| unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFD) } >= 0) {
            result.write_all(b"STDIO_NOT_RESERVED").unwrap();
            std::process::exit(42);
        }
        let mut command = Command::new("/bin/true");
        unsafe {
            command.pre_exec(move || {
                for fd in 0..3 {
                    if nix::libc::dup2(raw, fd) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Err(std::io::Error::from_raw_os_error(nix::libc::EACCES))
            });
        }
        let refusal = command
            .spawn()
            .expect_err("pre-exec error must reach original std pipe");
        assert_eq!(refusal.raw_os_error(), Some(nix::libc::EACCES));
        let mut status = 0;
        assert_eq!(
            unsafe { nix::libc::waitpid(-1, &mut status, nix::libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(nix::libc::ECHILD)
        );
        drop(reservations);
        assert!((0..3).all(|fd| unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFD) } < 0));
        result.write_all(b"STDIO_GUARD_EXEC_ERROR_REAPED").unwrap();
        std::process::exit(0);
    }
    struct Owned(Option<std::process::Child>);
    impl Drop for Owned {
        fn drop(&mut self) {
            if let Some(child) = &mut self.0 {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
    let temporary = tempfile::tempdir().unwrap();
    let record = temporary.path().join("result");
    let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let child=Command::new(std::env::current_exe().unwrap()).args(["--exact","darwin_process_scope::keeper_tests::keeper_closed_stdio_preserves_exec_error_handshake","--nocapture"]).env(CHILD,&record).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let mut child = Owned(Some(child));
    let status = loop {
        if let Some(status) = child.0.as_mut().unwrap().try_wait().unwrap() {
            break status;
        }
        assert!(
            std::time::Instant::now() < end,
            "owned stdio source control timed out"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    child.0.take();
    let observed = std::fs::read(&record).unwrap_or_default();
    assert_eq!(observed, b"STDIO_GUARD_EXEC_ERROR_REAPED");
    assert!(status.success());
}

#[test]
fn keeper_created_drop_retains_the_admitted_cleanup_obligation() {
    use super::keeper_pty::{Created, Master, Startup};
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    };
    use transport::channel_open::{CleanupAuthority, CleanupStatus, OpenCustody};
    use transport::channel_server::{ChannelWait, ChildStatus};
    struct Wait {
        allow: Arc<AtomicBool>,
        drops: Arc<AtomicUsize>,
    }
    impl Drop for Wait {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }
    impl ChannelWait for Wait {
        fn poll_exit(&mut self) -> ChildStatus {
            ChildStatus::Running
        }
        fn kill(&mut self) {}
        fn wait(self: Box<Self>) -> i32 {
            panic!("drop is not a wait receipt")
        }
        fn cleanup_uninstalled(&mut self, authority: &CleanupAuthority<'_>) -> CleanupStatus {
            if self.allow.load(Ordering::SeqCst) {
                authority.reaped()
            } else {
                CleanupStatus::Unknown
            }
        }
    }
    let custody = OpenCustody::new();
    let allow = Arc::new(AtomicBool::new(false));
    let drops = Arc::new(AtomicUsize::new(0));
    let created = Created::new(
        Box::new(Master::new(tempfile::tempfile().unwrap())),
        Box::new(Wait {
            allow: allow.clone(),
            drops: drops.clone(),
        }),
        Startup::Pending,
        &custody,
        Box::new(transport::shell_server::NoScreen),
    );
    drop(created);
    assert_eq!(
        drops.load(Ordering::SeqCst),
        0,
        "dropping Created abandoned its child owner"
    );
    assert!(matches!(custody.cleanup(), CleanupStatus::Unknown));
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    allow.store(true, Ordering::SeqCst);
    assert!(matches!(custody.cleanup(), CleanupStatus::Confirmed(_)));
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn keeper_master_read_preserves_pty_eof_and_other_errors() {
    use super::keeper_pty::master_read_result;
    assert_eq!(
        master_read_result(Err(std::io::Error::from_raw_os_error(nix::libc::EIO))).unwrap(),
        0
    );
    assert_eq!(master_read_result(Ok(7)).unwrap(), 7);
    assert_eq!(
        master_read_result(Err(std::io::Error::from_raw_os_error(nix::libc::EBADF)))
            .unwrap_err()
            .raw_os_error(),
        Some(nix::libc::EBADF)
    );
}

#[cfg(target_os = "macos")]
mod native_fixture {
    use super::super::{
        keeper::{FixtureAuthority, FixtureSnapshot, KeeperOwner},
        keeper_pty::ImageSource,
    };
    use nix::libc;
    use std::io::{self, Read, Write};
    use std::os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        process::CommandExt,
    };
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    };
    use std::time::{Duration, Instant};
    use transport::{
        auth::Principal,
        channel::{ChannelKind, OpenRequest},
        channel_open::{
            ChannelOpenRegistry, OpenCustody, OpenLimits, SpawnFailure, UninstalledChannel,
        },
        channel_server::{ChannelSpawner, ChildStatus, SpawnedChannel},
        session_manager::LoginId,
    };
    const MODE: &str = "QSH_KEEPER_APPLICATION_FIXTURE";
    const DIRECTORY: &str = "QSH_KEEPER_APPLICATION_DIRECTORY";
    const NONCE: &str = "QSH_KEEPER_APPLICATION_NONCE";
    const DEADLINE: &str = "QSH_KEEPER_APPLICATION_DEADLINE";
    static ENVIRONMENT: Mutex<()> = Mutex::new(());
    fn monotonic() -> u128 {
        let mut value: libc::timespec = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) },
            0
        );
        value.tv_sec as u128 * 1_000_000_000 + value.tv_nsec as u128
    }
    struct Deadline {
        raw: u128,
        end: Instant,
    }
    impl Deadline {
        fn new() -> Self {
            Self {
                raw: monotonic() + 60_000_000_000,
                end: Instant::now() + Duration::from_secs(60),
            }
        }
        fn valid(&self) -> bool {
            monotonic() < self.raw && Instant::now() < self.end
        }
    }
    struct Environment {
        saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
        mask: libc::mode_t,
        _home: tempfile::TempDir,
    }
    impl Environment {
        fn set(mode: &str, nonce: &str, deadline: u128) -> Self {
            let home = tempfile::Builder::new()
                .prefix("qsh-keeper-control-")
                .tempdir()
                .unwrap();
            std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let mask = unsafe { libc::umask(0o077) };
            let mut saved = Vec::new();
            for key in ["HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "TMPDIR"] {
                saved.push((key, std::env::var_os(key)));
                let dir = home.path().join(key);
                std::fs::create_dir(&dir).unwrap();
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
                std::env::set_var(key, dir);
            }
            for (key, value) in [
                (MODE, Some(mode.to_owned())),
                (NONCE, Some(nonce.to_owned())),
                (DEADLINE, Some(deadline.to_string())),
                (DIRECTORY, None),
                ("HISTFILE", Some("/dev/null".into())),
                ("SSH_AUTH_SOCK", None),
                ("SSH_AGENT_PID", None),
            ] {
                saved.push((key, std::env::var_os(key)));
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
            Self {
                saved,
                mask,
                _home: home,
            }
        }
        fn directory(&mut self, path: &Path) {
            std::env::set_var(DIRECTORY, path);
        }
    }
    impl Drop for Environment {
        fn drop(&mut self) {
            for (key, value) in self.saved.drain(..).rev() {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
            unsafe { libc::umask(self.mask) };
        }
    }
    fn exclusive(path: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        file.write_all(bytes)
    }
    fn read_gate(path: &Path) -> io::Result<Vec<u8>> {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let meta = file.metadata()?;
        if !meta.is_file()
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.mode() & 0o777 != 0o600
            || meta.len() > 256
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut bytes = Vec::new();
        file.take(257).read_to_end(&mut bytes)?;
        if bytes.len() > 256 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(bytes)
    }
    fn actor_environment() -> Option<(String, PathBuf, String, u128)> {
        let mode = std::env::var(MODE).ok()?;
        let directory =
            PathBuf::from(std::env::var_os(DIRECTORY).expect("required fixture directory"));
        let nonce = std::env::var(NONCE).expect("required fixture nonce");
        assert!(
            nonce.len() == 32
                && nonce
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        let end = std::env::var(DEADLINE).unwrap().parse::<u128>().unwrap();
        assert!(monotonic() < end);
        let meta = std::fs::symlink_metadata(&directory).unwrap();
        assert!(
            meta.is_dir()
                && meta.uid() == unsafe { libc::geteuid() }
                && meta.mode() & 0o777 == 0o700
        );
        assert_eq!(directory.parent(), Some(std::env::temp_dir().as_path()));
        assert!(directory
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("qsh-keeper-native-"));
        assert_eq!(
            read_gate(&directory.join("instance")).unwrap(),
            nonce.as_bytes()
        );
        Some((mode, directory, nonce, end))
    }
    fn event(nonce: &str, kind: &str, values: &[i32]) {
        let mut line = format!("KEEPER_EVENT {nonce} {kind}");
        for value in values {
            line.push(' ');
            line.push_str(&value.to_string());
        }
        line.push('\n');
        assert!(line.len() <= 256);
        std::io::stdout().write_all(line.as_bytes()).unwrap();
        std::io::stdout().flush().unwrap();
    }
    fn line(expected: &str, end: u128) {
        let flags = unsafe { libc::fcntl(0, libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(0, libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0
        );
        let mut bytes = Vec::new();
        while monotonic() < end {
            let mut byte = 0;
            let n = unsafe { libc::read(0, (&mut byte as *mut u8).cast(), 1) };
            if n == 1 {
                bytes.push(byte);
                assert!(bytes.len() <= 64);
                if byte == b'\n' {
                    assert_eq!(bytes, format!("{expected}\n").as_bytes());
                    return;
                }
            } else if n == 0 {
                panic!("fixture input closed before gate");
            } else {
                assert!(matches!(
                    io::Error::last_os_error().kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ));
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        panic!("fixture input exceeded original deadline");
    }
    fn wait_release(path: &Path, nonce: &str, end: u128) {
        loop {
            assert!(
                monotonic() < end,
                "fixture release exceeded original deadline"
            );
            match read_gate(path) {
                Ok(bytes) => {
                    assert_eq!(bytes, nonce.as_bytes());
                    return;
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(_) => panic!("fixture release gate refused"),
            }
        }
    }
    fn ignore_hup() {
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = libc::SIG_IGN;
        assert_eq!(unsafe { libc::sigemptyset(&mut action.sa_mask) }, 0);
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGHUP, &action, std::ptr::null_mut()) },
            0
        );
    }
    pub fn actor(case: &str) -> bool {
        let Some((mode, directory, nonce, end)) = actor_environment() else {
            return false;
        };
        if mode == "late-intruder" || mode == "late-child" {
            ignore_hup();
            while monotonic() < end {
                std::thread::sleep(Duration::from_millis(5));
            }
            std::process::exit(125);
        }
        assert_eq!(mode, case);
        let pid = unsafe { libc::getpid() };
        let sid = unsafe { libc::getsid(0) };
        let group = unsafe { libc::getpgrp() };
        let foreground = unsafe { libc::tcgetpgrp(0) };
        assert_eq!(unsafe { libc::isatty(0) }, 1);
        assert_eq!(group, pid);
        assert_eq!(foreground, group);
        event(&nonce, "READY", &[pid, sid, group, foreground]);
        if case == "normal" {
            for fd in 0..3 {
                assert_eq!(unsafe { libc::close(fd) }, 0);
            }
            exclusive(&directory.join("stdio-closed"), nonce.as_bytes()).unwrap();
            loop {
                assert!(
                    monotonic() < end,
                    "fixture release exceeded original deadline"
                );
                match read_gate(&directory.join("release")) {
                    Ok(bytes) => {
                        assert_eq!(bytes, nonce.as_bytes());
                        break;
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(_) => panic!("fixture release gate refused"),
                }
            }
            std::process::exit(37);
        }
        ignore_hup();
        if case == "late" {
            let selector =
                "darwin_process_scope::keeper_tests::keeper_native_session_death_late_fork";
            let mut intruder = Command::new(std::env::current_exe().unwrap());
            intruder
                .args(["--exact", selector, "--nocapture"])
                .env(MODE, "late-intruder")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            unsafe {
                intruder.pre_exec(move || {
                    if libc::setpgid(0, sid) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let mut intruder = intruder.spawn().unwrap();
            assert_eq!(unsafe { libc::getpgid(intruder.id() as i32) }, sid);
            event(&nonce, "S_INTRUSION", &[intruder.id() as i32]);
            line("KILL_S", end);
            assert_eq!(unsafe { libc::kill(-sid, libc::SIGKILL) }, 0);
            assert!(!intruder.wait().unwrap().success());
            // Session-leader death can hang up the controlling PTY. From this
            // point synchronization is ordinary post-exec private file I/O.
            exclusive(&directory.join("s-killed"), nonce.as_bytes()).unwrap();
            wait_release(&directory.join("fork-late"), &nonce, end);
            let mut late = Command::new(std::env::current_exe().unwrap());
            late.args(["--exact", selector, "--nocapture"])
                .env(MODE, "late-child")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            unsafe {
                late.pre_exec(|| {
                    if libc::setpgid(0, 0) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let late = late.spawn().unwrap();
            let late_pid = late.id() as i32;
            assert_eq!(unsafe { libc::getpgid(late_pid) }, late_pid);
            exclusive(
                &directory.join("late-created"),
                format!("{nonce} {late_pid}").as_bytes(),
            )
            .unwrap();
            wait_release(&directory.join("exit-a"), &nonce, end);
            // The scoped watcher/keeper owner now holds the descendant's exit
            // obligation; after A exits it is intentionally a nondirect child.
            drop(late);
            std::process::exit(37);
        }
        assert_eq!(case, "intrusion");
        line("JOIN_B", end);
        let broker = unsafe { libc::getppid() };
        assert_eq!(unsafe { libc::setpgid(0, broker) }, 0);
        assert_eq!(unsafe { libc::getpgrp() }, broker);
        event(&nonce, "IN_B", &[pid, broker]);
        while monotonic() < end {
            std::thread::sleep(Duration::from_millis(5));
        }
        std::process::exit(125);
    }
    struct Spawner {
        registry: Arc<ChannelOpenRegistry>,
        authority: Arc<Mutex<Option<FixtureAuthority>>>,
        end: Instant,
        image: PathBuf,
        sha256: String,
    }
    impl ChannelSpawner for Spawner {
        fn open_registry(&self) -> Arc<ChannelOpenRegistry> {
            Arc::clone(&self.registry)
        }
        fn spawn(
            &self,
            _: &Principal,
            _: LoginId,
            request: &OpenRequest,
            term: Option<&str>,
            custody: &OpenCustody,
        ) -> Result<UninstalledChannel, SpawnFailure> {
            let created = KeeperOwner::spawn(
                ImageSource::Fixture {
                    path: self.image.clone(),
                    sha256: self.sha256.clone(),
                },
                Some(&request.command),
                portable_pty::PtySize {
                    rows: request.rows,
                    cols: request.cols,
                    pixel_width: 0,
                    pixel_height: 0,
                },
                term,
                self.end,
                custody,
                Box::new(transport::shell_server::NoScreen),
            )?;
            *self.authority.lock().unwrap() = created.fixture_authority();
            let fd = created
                .fixture_master_fd()
                .expect("actual keeper master descriptor");
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
            {
                drop(created);
                return Err(custody.failure("fixture master cannot be observed".into()));
            }
            created.finish()
        }
    }
    struct IoWorkers {
        stop: Arc<AtomicBool>,
        events: mpsc::Receiver<String>,
        eof: Arc<AtomicBool>,
        sender: Option<mpsc::SyncSender<String>>,
        reader: Option<std::thread::JoinHandle<io::Result<()>>>,
        writer: Option<std::thread::JoinHandle<io::Result<()>>>,
    }
    impl IoWorkers {
        fn start(channel: &mut Option<SpawnedChannel>, nonce: String, end: Instant) -> Self {
            let channel = channel.as_mut().unwrap();
            let reader = std::mem::replace(&mut channel.reader, Box::new(io::empty()));
            let writer = std::mem::replace(&mut channel.writer, Box::new(io::sink()));
            let stop = Arc::new(AtomicBool::new(false));
            let eof = Arc::new(AtomicBool::new(false));
            let (tx, events) = mpsc::sync_channel(16);
            let (sender, rx) = mpsc::sync_channel::<String>(16);
            let reader_stop = Arc::clone(&stop);
            let reader_eof = Arc::clone(&eof);
            let read_thread = std::thread::spawn(move || {
                let mut reader = reader;
                let mut buffer = [0; 512];
                let mut line = Vec::new();
                let mut total = 0usize;
                while Instant::now() < end && !reader_stop.load(Ordering::SeqCst) {
                    match reader.read(&mut buffer) {
                        Ok(0) => {
                            reader_eof.store(true, Ordering::SeqCst);
                            return Ok(());
                        }
                        Ok(n) => {
                            total += n;
                            if total > 64 * 1024 {
                                return Err(io::ErrorKind::InvalidData.into());
                            }
                            for byte in &buffer[..n] {
                                line.push(*byte);
                                if line.len() > 1024 {
                                    return Err(io::ErrorKind::InvalidData.into());
                                }
                                if *byte == b'\n' {
                                    let text = String::from_utf8_lossy(&line).replace('\r', "");
                                    if let Some(record) =
                                        text.strip_prefix(&format!("KEEPER_EVENT {nonce} "))
                                    {
                                        tx.try_send(record.trim_end().to_owned())
                                            .map_err(|_| io::ErrorKind::InvalidData)?;
                                    }
                                    line.clear();
                                }
                            }
                        }
                        Err(e)
                            if matches!(
                                e.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                            ) =>
                        {
                            std::thread::sleep(Duration::from_millis(5))
                        }
                        Err(e) => return Err(e),
                    }
                }
                Err(io::ErrorKind::TimedOut.into())
            });
            let writer_stop = Arc::clone(&stop);
            let write_thread = std::thread::spawn(move || {
                let mut writer = writer;
                while Instant::now() < end && !writer_stop.load(Ordering::SeqCst) {
                    match rx.recv_timeout(Duration::from_millis(5)) {
                        Ok(line) => {
                            let bytes = format!("{line}\n").into_bytes();
                            let mut at = 0;
                            while at < bytes.len()
                                && Instant::now() < end
                                && !writer_stop.load(Ordering::SeqCst)
                            {
                                match writer.write(&bytes[at..]) {
                                    Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                                    Ok(n) => at += n,
                                    Err(e)
                                        if matches!(
                                            e.kind(),
                                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                                        ) =>
                                    {
                                        std::thread::sleep(Duration::from_millis(5))
                                    }
                                    Err(e) => return Err(e),
                                }
                            }
                            if at != bytes.len() {
                                return Err(io::ErrorKind::TimedOut.into());
                            }
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
                    }
                }
                Err(io::ErrorKind::TimedOut.into())
            });
            Self {
                stop,
                events,
                eof,
                sender: Some(sender),
                reader: Some(read_thread),
                writer: Some(write_thread),
            }
        }
        fn send(&self, value: &str) {
            self.sender
                .as_ref()
                .unwrap()
                .try_send(value.to_owned())
                .expect("bounded fixture input");
        }
        fn finish(&mut self, end: Instant) -> bool {
            self.sender.take();
            let mut ok = true;
            for worker in [&mut self.reader, &mut self.writer] {
                if let Some(thread) = worker.take() {
                    while !thread.is_finished() && Instant::now() < end {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    if !thread.is_finished() {
                        eprintln!("KEEPER_FIXTURE_UNSETTLED_IO");
                        std::process::abort();
                    }
                    ok &= thread.join().is_ok_and(|result| result.is_ok());
                }
            }
            ok
        }
    }
    struct Case {
        authority: Arc<Mutex<Option<FixtureAuthority>>>,
        channel: Option<SpawnedChannel>,
        io: Option<IoWorkers>,
        complete: bool,
        deadline: Deadline,
        nonce: String,
        directory: tempfile::TempDir,
        _spawner: Spawner,
        _environment: Environment,
    }
    impl Case {
        fn new(case: &str, selector: &str) -> Self {
            let deadline = Deadline::new();
            let mut nonce = [0; 16];
            rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);
            let nonce = hex::encode(nonce);
            let mut environment = Environment::set(case, &nonce, deadline.raw);
            let directory = tempfile::Builder::new()
                .prefix("qsh-keeper-native-")
                .tempdir_in(std::env::var_os("TMPDIR").unwrap())
                .unwrap();
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            environment.directory(directory.path());
            exclusive(&directory.path().join("instance"), nonce.as_bytes()).unwrap();
            let image = PathBuf::from(
                std::env::var_os("QSH_DARWIN223_DAEMON")
                    .expect("required source-bound Cargo daemon path"),
            );
            let sha256 = std::env::var("QSH_DARWIN223_DAEMON_SHA256")
                .expect("required Cargo artifact digest");
            let authority = Arc::new(Mutex::new(None));
            let spawner = Spawner {
                registry: ChannelOpenRegistry::new(OpenLimits::default()),
                authority: Arc::clone(&authority),
                end: deadline.end,
                image,
                sha256,
            };
            let mut fixture = Self {
                authority,
                channel: None,
                io: None,
                complete: false,
                deadline,
                nonce,
                directory,
                _spawner: spawner,
                _environment: environment,
            };
            let executable = std::env::current_exe().unwrap();
            let executable = executable.to_str().expect("fixture path UTF-8");
            assert!(!executable.contains('\''));
            let request = OpenRequest {
                stream: 16,
                kind: ChannelKind::Command,
                cols: 80,
                rows: 24,
                screen: false,
                command: format!("'{executable}' --exact {selector} --nocapture").into_bytes(),
            };
            let owner = Principal {
                uid: unsafe { libc::geteuid() },
                name: "keeper-fixture".into(),
                identity: "keeper-fixture".into(),
                incarnation: 0,
            };
            let channel = crate::channel_backend::fixture_spawn(
                &fixture._spawner,
                &owner,
                [0; 16],
                &request,
                Some("xterm-256color"),
            )
            .expect("actual protected keeper fixture creation");
            fixture.channel = Some(channel);
            fixture.io = Some(IoWorkers::start(
                &mut fixture.channel,
                fixture.nonce.clone(),
                fixture.deadline.end,
            ));
            fixture
        }
        fn authority(&self) -> FixtureAuthority {
            self.authority
                .lock()
                .unwrap()
                .clone()
                .expect("actual keeper authority")
        }
        fn snapshot(&self) -> FixtureSnapshot {
            self.authority()
                .snapshot()
                .expect("nonblocking keeper snapshot")
        }
        fn tick(&mut self) -> ChildStatus {
            assert!(
                self.deadline.valid(),
                "original keeper case deadline expired"
            );
            let status = self.channel.as_mut().unwrap().wait.poll_exit();
            assert!(
                !matches!(status, ChildStatus::Unknown(_)),
                "keeper ownership became unknown"
            );
            status
        }
        fn until(&mut self, mut condition: impl FnMut(&mut Self) -> bool) {
            while !condition(self) {
                self.tick();
                std::thread::sleep(Duration::from_millis(5));
            }
            assert!(self.deadline.valid());
        }
        fn event(&mut self, kind: &str) -> Vec<i32> {
            loop {
                self.tick();
                match self.io.as_ref().unwrap().events.try_recv() {
                    Ok(event) => {
                        let mut fields = event.split_whitespace();
                        assert_eq!(fields.next(), Some(kind), "unexpected fixed actor stage");
                        return fields
                            .map(|s| s.parse::<i32>().expect("numeric actor field"))
                            .collect();
                    }
                    Err(mpsc::TryRecvError::Empty) => std::thread::sleep(Duration::from_millis(5)),
                    Err(_) => panic!("fixture event stream ended"),
                }
            }
        }
        fn finish(&mut self, expected: i32) -> FixtureSnapshot {
            loop {
                match self.tick() {
                    ChildStatus::Reaped { code } => {
                        assert_eq!(code, Some(expected));
                        break;
                    }
                    _ => std::thread::sleep(Duration::from_millis(5)),
                }
            }
            let snapshot = self.snapshot();
            assert_eq!(snapshot.app_status, Some(expected));
            assert!(snapshot.broker_terminal && snapshot.drained && snapshot.census);
            assert!(snapshot.session_wait.is_some());
            assert!(snapshot
                .keepers
                .iter()
                .all(|k| k.2.is_some() && k.3.is_some()));
            assert!(self.io.as_mut().unwrap().finish(self.deadline.end));
            assert!(self.io.as_ref().unwrap().eof.load(Ordering::SeqCst));
            self.complete = true;
            snapshot
        }
    }
    impl Drop for Case {
        fn drop(&mut self) {
            if !self.complete {
                if let Some(io) = &mut self.io {
                    io.stop.store(true, Ordering::SeqCst);
                    io.sender.take();
                }
                let end = Instant::now() + Duration::from_secs(10);
                if let Some(authority) = self
                    .authority
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .clone()
                {
                    if !authority.rescue(end) {
                        eprintln!("KEEPER_FIXTURE_UNSETTLED_ACTORS");
                    }
                }
                if let Some(io) = &mut self.io {
                    let _ = io.finish(end);
                }
            }
        }
    }
    pub fn normal() {
        let _serial = ENVIRONMENT.lock().unwrap_or_else(|p| p.into_inner());
        let mut case = Case::new(
            "normal",
            "darwin_process_scope::keeper_tests::keeper_native_exit37_and_pty_eof",
        );
        let ready = case.event("READY");
        let initial = case.snapshot();
        assert_eq!(ready.len(), 4);
        assert_eq!(Some(ready[0]), initial.app);
        assert_eq!(ready[1], initial.sid);
        assert_eq!(ready[2], ready[0]);
        assert_eq!(ready[3], ready[2]);
        case.until(|fixture| {
            read_gate(&fixture.directory.path().join("stdio-closed"))
                .is_ok_and(|bytes| bytes == fixture.nonce.as_bytes())
        });
        case.until(|fixture| fixture.io.as_ref().unwrap().eof.load(Ordering::SeqCst));
        let live = case.snapshot();
        assert_eq!(live.app_status, None);
        assert_eq!(live.session_status, None);
        assert!(!live.broker_terminal);
        assert_eq!(live.session_wait, None);
        exclusive(
            &case.directory.path().join("release"),
            case.nonce.as_bytes(),
        )
        .unwrap();
        let result = case.finish(37);
        assert_eq!(result.session_wait, Some(0));
        eprintln!(
            "keeper223 case=exit37 app=37 session=0 broker_exit=true io_joined=2 rescue=false"
        );
    }
    pub fn late() {
        let _serial = ENVIRONMENT.lock().unwrap_or_else(|p| p.into_inner());
        let mut case = Case::new(
            "late",
            "darwin_process_scope::keeper_tests::keeper_native_session_death_late_fork",
        );
        let ready = case.event("READY");
        assert_eq!(ready.len(), 4);
        let intrusion = case.event("S_INTRUSION");
        assert_eq!(intrusion.len(), 1);
        case.io.as_ref().unwrap().send("KILL_S");
        case.until(|fixture| {
            read_gate(&fixture.directory.path().join("s-killed"))
                .is_ok_and(|bytes| bytes == fixture.nonce.as_bytes())
        });
        case.until(|fixture| {
            let snapshot = fixture.snapshot();
            snapshot.session_status.is_some()
                && snapshot.session_wait.is_none()
                && snapshot.broker_parent == Some(1)
        });
        exclusive(
            &case.directory.path().join("fork-late"),
            case.nonce.as_bytes(),
        )
        .unwrap();
        case.until(|fixture| read_gate(&fixture.directory.path().join("late-created")).is_ok());
        let late = read_gate(&case.directory.path().join("late-created")).unwrap();
        let late = std::str::from_utf8(&late).unwrap();
        let mut fields = late.split_whitespace();
        assert_eq!(fields.next(), Some(case.nonce.as_str()));
        let late = fields.next().unwrap().parse::<i32>().unwrap();
        assert!(fields.next().is_none());
        exclusive(&case.directory.path().join("exit-a"), case.nonce.as_bytes()).unwrap();
        let result = case.finish(37);
        assert_eq!(result.broker_parent, Some(1));
        assert_eq!(result.session_wait, Some(1));
        assert!(result.keepers.iter().any(|k| k.1 == Some(late)));
        eprintln!("keeper223 case=late-fork app=37 session=1 broker_parent=1 broker_exit=true io_joined=2 rescue=false");
    }
    pub fn intrusion() {
        let _serial = ENVIRONMENT.lock().unwrap_or_else(|p| p.into_inner());
        let mut case = Case::new(
            "intrusion",
            "darwin_process_scope::keeper_tests::keeper_native_broker_group_intrusion",
        );
        let ready = case.event("READY");
        assert_eq!(ready.len(), 4);
        case.io.as_ref().unwrap().send("JOIN_B");
        let joined = case.event("IN_B");
        let before = case.snapshot();
        assert_eq!(joined.len(), 2);
        assert_eq!(Some(joined[0]), before.app);
        assert_eq!(joined[1], before.broker.unwrap().pid);
        case.channel.as_mut().unwrap().wait.kill();
        let result = case.finish(1);
        assert!(!result.moves.is_empty());
        assert!(result.moves.iter().all(|group| *group != joined[1]));
        assert!(result
            .keepers
            .iter()
            .any(|k| k.1 == Some(joined[1]) && k.2 == Some(1) && k.3 == Some(1)));
        eprintln!("keeper223 case=broker-intrusion app=1 broker_relocated=true killed_keeper_waited=true broker_exit=true io_joined=2 rescue=false");
    }
}

#[cfg(target_os = "macos")]
#[test]
fn keeper_native_exit37_and_pty_eof() {
    if !native_fixture::actor("normal") {
        native_fixture::normal();
    }
}
#[cfg(target_os = "macos")]
#[test]
fn keeper_native_session_death_late_fork() {
    if !native_fixture::actor("late") {
        native_fixture::late();
    }
}
#[cfg(target_os = "macos")]
#[test]
fn keeper_native_broker_group_intrusion() {
    if !native_fixture::actor("intrusion") {
        native_fixture::intrusion();
    }
}

#[test]
fn keeper_observed_member_session_escape_blocks_closing_until_terminal() {
    use super::keeper_helper::ApplicationDebt;
    use super::{Class, Classified, Identity};
    let descendant = Classified {
        identity: Identity {
            pid: 42,
            unique: 420,
            version: 1,
        },
        class: Class::Session(10),
    };
    let mut debt = ApplicationDebt::default();
    // B observes D before D calls setsid. A still owns its original wait.
    debt.reconcile(&[descendant], Ok(&[descendant]));
    assert!(!debt.can_close(false));
    let escaped = Classified {
        class: Class::Session(42),
        ..descendant
    };
    // D closes stdio and A exits 37: neither changes D's live identity.
    debt.reconcile(&[], Ok(&[escaped]));
    assert!(
        !debt.can_close(true),
        "live observed D escaped the SID-only census"
    );
    // An exec version change still belongs to the same live process.
    let executed = Classified {
        identity: Identity {
            version: 2,
            ..escaped.identity
        },
        ..escaped
    };
    debt.reconcile(&[], Ok(&[executed]));
    assert!(!debt.can_close(true));
    // Only a fresh successful full census's positive terminal evidence clears D.
    debt.reconcile(
        &[],
        Ok(&[Classified {
            class: Class::Zombie,
            ..executed
        }]),
    );
    assert!(debt.can_close(true));
}

#[test]
fn keeper_observed_debt_requires_positive_full_census_exclusion() {
    use super::keeper_helper::ApplicationDebt;
    use super::{Class, Classified, Failure, Identity};
    let member = Classified {
        identity: Identity {
            pid: 42,
            unique: 420,
            version: 1,
        },
        class: Class::Session(10),
    };
    for replacement in [
        None,
        Some(Classified {
            identity: Identity {
                unique: 421,
                ..member.identity
            },
            class: Class::Session(42),
        }),
    ] {
        let mut debt = ApplicationDebt::default();
        debt.reconcile(&[member], Ok(&[member]));
        for refusal in [Failure::Invalid, Failure::Capacity, Failure::Errno(1)] {
            // Partial, truncated or denied inspection is never an empty census.
            debt.reconcile(&[], Err(refusal));
            assert!(!debt.can_close(true));
        }
        let all: Vec<_> = replacement.into_iter().collect();
        debt.reconcile(&[], Ok(&all));
        assert!(
            !debt.can_close(false),
            "A's actual wait remains independently required"
        );
        assert!(debt.can_close(true));
    }
}
