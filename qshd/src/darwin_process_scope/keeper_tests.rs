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
        Operation::AbortBeforeAdmit,
        Operation::AppNotStarted,
    ]
    .into_iter()
    .enumerate()
    {
        let frame = Frame {
            operation,
            fields: if matches!(
                operation,
                Operation::AbortBeforeAdmit | Operation::AppNotStarted
            ) {
                [0; 4]
            } else {
                [i as i64, 37, -1, 0]
            },
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
    for (startup, cancelled) in [
        (Startup::Pending, false),
        (Startup::Failed("injected watch refusal".into()), false),
        (Startup::Ready, false),
        (Startup::Ready, true),
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
        if cancelled {
            custody.cancel();
        }
        let outcome = created.finish();
        if cancelled {
            assert!(outcome.is_err(), "cancelled Created became installable");
        }
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
        application: AppDisposition::Waited(37),
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
            application: AppDisposition::Waited(37),
            session_wait: Some(0),
            broker_terminal: true,
            final_census: true,
            drained: true,
        };
        match missing {
            0 => proof.application = AppDisposition::Pending,
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

mod late_diagnostics {
    // A diagnostic output failure must never interrupt the fixture's cleanup.
    pub(super) fn emit(writer: &mut impl std::io::Write, message: std::fmt::Arguments<'_>) {
        let _ = writer
            .write_fmt(message)
            .and_then(|()| writer.write_all(b"\n"));
    }

    #[derive(Clone, Copy)]
    pub(super) enum Phase {
        Ready,
        Intrusion,
        KillS,
        SKilled,
        SessionObserved,
        ForkLate,
        LateCreated,
        ExitA,
        Reap,
        FinalProof,
        IoJoin,
        FinalAssertions,
        Done,
    }
    impl Phase {
        pub(super) const ALL: [Self; 13] = [
            Self::Ready,
            Self::Intrusion,
            Self::KillS,
            Self::SKilled,
            Self::SessionObserved,
            Self::ForkLate,
            Self::LateCreated,
            Self::ExitA,
            Self::Reap,
            Self::FinalProof,
            Self::IoJoin,
            Self::FinalAssertions,
            Self::Done,
        ];
        pub(super) fn label(self) -> &'static str {
            match self {
                Self::Ready => "ready",
                Self::Intrusion => "intrusion",
                Self::KillS => "kill_s",
                Self::SKilled => "s_killed",
                Self::SessionObserved => "session_observed",
                Self::ForkLate => "fork_late",
                Self::LateCreated => "late_created",
                Self::ExitA => "exit_a",
                Self::Reap => "reap",
                Self::FinalProof => "final_proof",
                Self::IoJoin => "io_join",
                Self::FinalAssertions => "final_assertions",
                Self::Done => "done",
            }
        }
    }
    #[derive(Clone, Copy)]
    pub(super) enum Boundary {
        Begin,
        End,
        Checkpoint,
        Failure,
    }
    impl Boundary {
        fn label(self) -> &'static str {
            match self {
                Self::Begin => "begin",
                Self::End => "end",
                Self::Checkpoint => "checkpoint",
                Self::Failure => "failure",
            }
        }
    }
    #[derive(Clone, Copy)]
    pub(super) enum Gate {
        Unobserved,
        Missing,
        Refused,
        Mismatch,
        Readable,
        Valid,
        Written,
    }
    impl Gate {
        pub(super) fn label(self) -> &'static str {
            match self {
                Self::Unobserved => "unobserved",
                Self::Missing => "missing",
                Self::Refused => "refused",
                Self::Mismatch => "mismatch",
                Self::Readable => "readable",
                Self::Valid => "valid",
                Self::Written => "written",
            }
        }
    }
    #[derive(Clone, Copy)]
    pub(super) enum Poll {
        NotPolled,
        Running,
        WaitingWorkers,
        Reaped(Option<i32>),
        Unknown,
    }
    impl Poll {
        pub(super) fn label(self) -> &'static str {
            match self {
                Self::NotPolled => "not_polled",
                Self::Running => "running",
                Self::WaitingWorkers => "waiting_workers",
                Self::Reaped(_) => "reaped",
                Self::Unknown => "unknown",
            }
        }
    }
    #[derive(Clone, Copy)]
    pub(super) enum Worker {
        Absent,
        Running,
        Finished,
    }
    impl Worker {
        fn label(self) -> &'static str {
            match self {
                Self::Absent => "absent",
                Self::Running => "running",
                Self::Finished => "finished",
            }
        }
    }
    #[derive(Default)]
    pub(super) struct Snapshot {
        pub app_status: Option<i32>,
        pub session_status: Option<i32>,
        pub session_wait: Option<i32>,
        pub broker_parent: Option<i32>,
        pub broker_terminal: bool,
        pub custody_lost: bool,
        pub drained: bool,
        pub census: bool,
        pub consumed: bool,
        pub keepers: usize,
    }
    pub(super) struct Io {
        pub eof: bool,
        pub reader: Worker,
        pub writer: Worker,
    }
    pub(super) struct State {
        pub phase: Phase,
        pub boundary: Boundary,
        pub poll: Poll,
        pub s_killed: Gate,
        pub late_created: Gate,
        pub fork_late: Gate,
        pub exit_a: Gate,
    }
    impl State {
        pub(super) fn new() -> Self {
            Self {
                phase: Phase::Ready,
                boundary: Boundary::Begin,
                poll: Poll::NotPolled,
                s_killed: Gate::Unobserved,
                late_created: Gate::Unobserved,
                fork_late: Gate::Unobserved,
                exit_a: Gate::Unobserved,
            }
        }
        pub(super) fn line(
            &self,
            controller_instant_before_end: bool,
            snapshot: Option<Snapshot>,
            io: Option<Io>,
        ) -> String {
            let code = match self.poll {
                Poll::Reaped(code) => code,
                _ => None,
            };
            format!("keeper223 late_diag phase={} boundary={} controller_instant_before_end={} last_poll={} last_code={:?} last_s_killed={} last_late_created={} last_fork_late={} last_exit_a={} snapshot_available={} app_status={:?} session_status={:?} session_wait={:?} broker_parent={:?} broker_terminal={:?} custody_lost={:?} drained={:?} census={:?} consumed={:?} keepers={:?} io_available={} eof={:?} reader={} writer={}",self.phase.label(),self.boundary.label(),controller_instant_before_end,self.poll.label(),code,self.s_killed.label(),self.late_created.label(),self.fork_late.label(),self.exit_a.label(),snapshot.is_some(),snapshot.as_ref().and_then(|s|s.app_status),snapshot.as_ref().and_then(|s|s.session_status),snapshot.as_ref().and_then(|s|s.session_wait),snapshot.as_ref().and_then(|s|s.broker_parent),snapshot.as_ref().map(|s|s.broker_terminal),snapshot.as_ref().map(|s|s.custody_lost),snapshot.as_ref().map(|s|s.drained),snapshot.as_ref().map(|s|s.census),snapshot.as_ref().map(|s|s.consumed),snapshot.as_ref().map(|s|s.keepers),io.is_some(),io.as_ref().map(|i|i.eof),io.as_ref().map_or("absent",|i|i.reader.label()),io.as_ref().map_or("absent",|i|i.writer.label()))
        }
    }
}

#[cfg(target_os = "macos")]
mod native_fixture {
    use super::super::{
        keeper::{FixtureAuthority, FixtureSnapshot, KeeperOwner},
        keeper_pty::ImageSource,
    };
    use super::late_diagnostics::{self as diag, Boundary, Gate, Phase, Poll};
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
        let file = std::fs::OpenOptions::new()
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
        late_diagnostic: Option<diag::State>,
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
                late_diagnostic: (case == "late").then(diag::State::new),
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
        fn late_boundary(&mut self, phase: Phase, boundary: Boundary) {
            if let Some(state) = &mut self.late_diagnostic {
                state.phase = phase;
                state.boundary = boundary;
                diag::emit(
                    &mut io::stderr(),
                    format_args!(
                        "keeper223 late_phase phase={} boundary={}",
                        phase.label(),
                        match boundary {
                            Boundary::Begin => "begin",
                            Boundary::End => "end",
                            Boundary::Checkpoint => "checkpoint",
                            Boundary::Failure => "failure",
                        }
                    ),
                );
            }
        }
        fn late_report(&mut self, boundary: Boundary) {
            let Some(state) = &mut self.late_diagnostic else {
                return;
            };
            state.boundary = boundary;
            let snapshot = self
                .authority
                .try_lock()
                .ok()
                .and_then(|authority| authority.as_ref().and_then(FixtureAuthority::snapshot))
                .map(|snapshot| diag::Snapshot {
                    app_status: snapshot.app_status,
                    session_status: snapshot.session_status,
                    session_wait: snapshot.session_wait,
                    broker_parent: snapshot.broker_parent,
                    broker_terminal: snapshot.broker_terminal,
                    custody_lost: snapshot.custody_lost,
                    drained: snapshot.drained,
                    census: snapshot.census,
                    consumed: snapshot.consumed,
                    keepers: snapshot.keepers.len(),
                });
            let worker = |thread: &Option<std::thread::JoinHandle<io::Result<()>>>| match thread {
                None => diag::Worker::Absent,
                Some(thread) if thread.is_finished() => diag::Worker::Finished,
                Some(_) => diag::Worker::Running,
            };
            let io = self.io.as_ref().map(|io| diag::Io {
                eof: io.eof.load(Ordering::SeqCst),
                reader: worker(&io.reader),
                writer: worker(&io.writer),
            });
            diag::emit(
                &mut io::stderr(),
                format_args!(
                    "{}",
                    state.line(Instant::now() < self.deadline.end, snapshot, io)
                ),
            );
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
            if let Some(state) = &mut self.late_diagnostic {
                state.poll = match &status {
                    ChildStatus::Running => Poll::Running,
                    ChildStatus::WaitingForWorkers => Poll::WaitingWorkers,
                    ChildStatus::Reaped { code } => Poll::Reaped(*code),
                    ChildStatus::Unknown(_) => Poll::Unknown,
                };
            }
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
            self.late_boundary(Phase::Reap, Boundary::Begin);
            loop {
                match self.tick() {
                    ChildStatus::Reaped { code } => {
                        assert_eq!(code, Some(expected));
                        break;
                    }
                    _ => std::thread::sleep(Duration::from_millis(5)),
                }
            }
            self.late_boundary(Phase::Reap, Boundary::End);
            self.late_boundary(Phase::FinalProof, Boundary::Begin);
            let snapshot = self.snapshot();
            assert_eq!(snapshot.app_status, Some(expected));
            assert!(snapshot.broker_terminal && snapshot.drained && snapshot.census);
            assert!(snapshot.session_wait.is_some());
            assert!(snapshot
                .keepers
                .iter()
                .all(|k| k.2.is_some() && k.3.is_some()));
            self.late_boundary(Phase::FinalProof, Boundary::End);
            self.late_boundary(Phase::IoJoin, Boundary::Begin);
            self.late_report(Boundary::Checkpoint);
            assert!(self.io.as_mut().unwrap().finish(self.deadline.end));
            assert!(self.io.as_ref().unwrap().eof.load(Ordering::SeqCst));
            self.late_boundary(Phase::IoJoin, Boundary::End);
            self.complete = true;
            snapshot
        }
    }
    impl Drop for Case {
        fn drop(&mut self) {
            if self.late_diagnostic.is_some() && (std::thread::panicking() || !self.complete) {
                self.late_report(Boundary::Failure);
            }
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
    pub fn cancel_no_application() {
        use transport::channel_open::{CleanupStatus, OpenIdentity, OpenRequestSnapshot};
        let _serial = ENVIRONMENT.lock().unwrap_or_else(|p| p.into_inner());
        let original_deadline = Deadline::new();
        for scenario in 0..3 {
            let after_admit = scenario == 1;
            let expired = scenario == 2;
            let deadline = Deadline {
                raw: original_deadline.raw,
                end: original_deadline.end,
            };
            let mut nonce = [0; 16];
            rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);
            let nonce = hex::encode(nonce);
            let mut environment = Environment::set("cancel", &nonce, deadline.raw);
            let directory = tempfile::Builder::new()
                .prefix("qsh-keeper-native-")
                .tempdir_in(std::env::var_os("TMPDIR").unwrap())
                .unwrap();
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            environment.directory(directory.path());
            exclusive(&directory.path().join("instance"), nonce.as_bytes()).unwrap();
            let image = PathBuf::from(
                std::env::var_os("QSH_DARWIN223_DAEMON").expect("source-bound Cargo daemon"),
            );
            let sha256 = std::env::var("QSH_DARWIN223_DAEMON_SHA256").expect("Cargo daemon digest");
            let authority = Arc::new(Mutex::new(None));
            let spawner = Spawner {
                registry: ChannelOpenRegistry::new(OpenLimits::default()),
                authority: Arc::clone(&authority),
                end: deadline.end,
                image,
                sha256,
            };
            let mut case = Case {
                authority,
                channel: None,
                io: None,
                complete: false,
                late_diagnostic: None,
                deadline,
                nonce,
                directory,
                _spawner: spawner,
                _environment: environment,
            };
            let marker = case.directory.path().join("application-started");
            let marker_text = marker.to_str().unwrap();
            assert!(!marker_text.contains('\''));
            let request = OpenRequest {
                stream: 16,
                kind: ChannelKind::Command,
                cols: 80,
                rows: 24,
                screen: false,
                command: format!(
                    "/bin/sh -c 'echo started > \"{marker_text}\"; exec /bin/sleep 45'"
                )
                .into_bytes(),
            };
            let owner = Principal {
                uid: unsafe { libc::geteuid() },
                name: "keeper-fixture".into(),
                identity: "keeper-fixture".into(),
                incarnation: 0,
            };
            let registry = Arc::clone(&case._spawner.registry);
            let session = registry.session().unwrap();
            let job = registry
                .try_reserve(
                    &session,
                    OpenRequestSnapshot {
                        owner,
                        login: [0; 16],
                        request: request.clone(),
                        term: Some("xterm-256color".into()),
                        identity: OpenIdentity {
                            session: session.id(),
                            instance: transport::channel_geometry::ChannelInstance::new(1).unwrap(),
                            stream: 16,
                            generation: 0,
                            invalidation_epoch: 0,
                        },
                    },
                )
                .unwrap();
            assert_eq!(registry.outstanding(), 1);
            let created = KeeperOwner::spawn(
                ImageSource::Fixture {
                    path: case._spawner.image.clone(),
                    sha256: case._spawner.sha256.clone(),
                },
                Some(&request.command),
                portable_pty::PtySize {
                    rows: 24,
                    cols: 80,
                    pixel_width: 0,
                    pixel_height: 0,
                },
                Some("xterm-256color"),
                case.deadline.end,
                job.custody(),
                Box::new(transport::shell_server::NoScreen),
            )
            .unwrap_or_else(|failure| panic!("keeper creation refused: {}", failure.reason));
            let master_fd = created.fixture_master_fd().unwrap();
            let authority = created.fixture_authority().unwrap();
            *case.authority.lock().unwrap() = Some(authority.clone());
            let gate = authority.pause_admission(after_admit);
            let worker = std::thread::spawn(move || created.finish().is_err());
            while !gate.reached() {
                assert!(case.deadline.valid());
                std::thread::sleep(Duration::from_millis(5));
            }
            // reached acknowledges the driver is outside every metadata lock.
            // Observe repeated held polls, not a controller scheduling sleep.
            while gate.held_polls() < 3 {
                assert!(case.deadline.valid());
                assert!(
                    !worker.is_finished(),
                    "driver completed through a held gate"
                );
                std::thread::yield_now();
            }
            assert!(!worker.is_finished());
            assert_eq!(
                authority.snapshot().unwrap().decision,
                if after_admit {
                    super::AdmissionDecision::Admit
                } else {
                    super::AdmissionDecision::Pending
                }
            );
            // cancel() takes the actual registered custody mutex. The barrier
            // must leave this operation free to complete before it is released.
            if expired {
                gate.expire_startup();
            } else {
                job.cancel();
                assert!(job.custody().is_cancelled());
            }
            gate.release();
            while !worker.is_finished() {
                assert!(case.deadline.valid());
                std::thread::sleep(Duration::from_millis(5));
            }
            assert!(
                worker.join().unwrap(),
                "aborted Created became an installable channel"
            );
            if !after_admit {
                assert!(
                    gate.resumed(),
                    "decision did not resume in original driver iteration"
                );
            }
            let cleanup_registry = Arc::clone(&registry);
            let cleanup_id = job.id();
            let cleanup = std::thread::spawn(move || cleanup_registry.cleanup(cleanup_id));
            while !cleanup.is_finished() && case.deadline.valid() {
                std::thread::sleep(Duration::from_millis(5));
            }
            if !cleanup.is_finished() {
                // Failure-only fixture settlement, never a product certificate.
                eprintln!("KEEPER_FIXTURE_CLEANUP_TIMEOUT rescue=true");
                let rescue_end = Instant::now() + Duration::from_secs(10);
                let _ = authority.rescue(rescue_end);
                while !cleanup.is_finished() && Instant::now() < rescue_end {
                    std::thread::sleep(Duration::from_millis(5));
                }
                if !cleanup.is_finished() {
                    std::process::abort();
                }
                let _ = cleanup.join();
                panic!("keeper cancellation exceeded original fixture deadline");
            }
            assert!(
                matches!(cleanup.join().unwrap(), CleanupStatus::Confirmed(_)),
                "healthy cancellation lost custody"
            );
            assert!(case.deadline.valid());
            let proof = authority.snapshot().unwrap();
            assert!(!proof.custody_lost);
            assert!(proof.broker_terminal && proof.drained && proof.census && proof.consumed);
            assert_eq!(proof.session_wait, Some(0));
            if after_admit {
                assert!(proof.app.is_some() && proof.app_status.is_some());
                assert!(!proof.not_started);
            } else {
                assert!(proof.not_started);
                assert_eq!(proof.app, None);
                assert_eq!(proof.app_status, None);
                assert!(!marker.exists());
            }
            assert_eq!(unsafe { libc::fcntl(master_fd, libc::F_GETFD) }, -1);
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
            assert_eq!(registry.outstanding(), 0);
            assert_eq!(session.occupied(), 0);
            case.complete = true;
            eprintln!("keeper223 case=cancel after_admit={after_admit} expired={expired} noapp={} app={:?} session=0 broker_exit=true pty_closed=true credits=0 rescue=false",proof.not_started,proof.app_status);
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
        case.late_boundary(Phase::Ready, Boundary::Begin);
        let ready = case.event("READY");
        assert_eq!(ready.len(), 4);
        case.late_boundary(Phase::Ready, Boundary::End);
        case.late_boundary(Phase::Intrusion, Boundary::Begin);
        let intrusion = case.event("S_INTRUSION");
        assert_eq!(intrusion.len(), 1);
        case.late_boundary(Phase::Intrusion, Boundary::End);
        case.late_boundary(Phase::KillS, Boundary::Begin);
        case.io.as_ref().unwrap().send("KILL_S");
        case.late_boundary(Phase::KillS, Boundary::End);
        case.late_boundary(Phase::SKilled, Boundary::Begin);
        case.until(|fixture| {
            let result = read_gate(&fixture.directory.path().join("s-killed"));
            let valid = match &result {
                Ok(bytes) => bytes == fixture.nonce.as_bytes(),
                Err(_) => false,
            };
            if let Some(state) = &mut fixture.late_diagnostic {
                state.s_killed = match &result {
                    Ok(_) if valid => Gate::Valid,
                    Ok(_) => Gate::Mismatch,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => Gate::Missing,
                    Err(_) => Gate::Refused,
                };
            }
            valid
        });
        case.late_boundary(Phase::SKilled, Boundary::End);
        case.late_boundary(Phase::SessionObserved, Boundary::Begin);
        case.until(|fixture| {
            let snapshot = fixture.snapshot();
            snapshot.session_status.is_some()
                && snapshot.session_wait.is_none()
                && snapshot.broker_parent == Some(1)
        });
        case.late_boundary(Phase::SessionObserved, Boundary::End);
        case.late_boundary(Phase::ForkLate, Boundary::Begin);
        exclusive(
            &case.directory.path().join("fork-late"),
            case.nonce.as_bytes(),
        )
        .unwrap();
        if let Some(state) = &mut case.late_diagnostic {
            state.fork_late = Gate::Written;
        }
        case.late_boundary(Phase::ForkLate, Boundary::End);
        case.late_boundary(Phase::LateCreated, Boundary::Begin);
        case.until(|fixture| {
            let result = read_gate(&fixture.directory.path().join("late-created"));
            if let Some(state) = &mut fixture.late_diagnostic {
                state.late_created = match &result {
                    Ok(_) => Gate::Readable,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => Gate::Missing,
                    Err(_) => Gate::Refused,
                };
            }
            result.is_ok()
        });
        let late = read_gate(&case.directory.path().join("late-created")).unwrap();
        let late = std::str::from_utf8(&late).unwrap();
        let mut fields = late.split_whitespace();
        assert_eq!(fields.next(), Some(case.nonce.as_str()));
        let late = fields.next().unwrap().parse::<i32>().unwrap();
        assert!(fields.next().is_none());
        if let Some(state) = &mut case.late_diagnostic {
            state.late_created = Gate::Valid;
        }
        case.late_boundary(Phase::LateCreated, Boundary::End);
        case.late_boundary(Phase::ExitA, Boundary::Begin);
        exclusive(&case.directory.path().join("exit-a"), case.nonce.as_bytes()).unwrap();
        if let Some(state) = &mut case.late_diagnostic {
            state.exit_a = Gate::Written;
        }
        case.late_boundary(Phase::ExitA, Boundary::End);
        let result = case.finish(37);
        case.late_boundary(Phase::FinalAssertions, Boundary::Begin);
        assert_eq!(result.broker_parent, Some(1));
        assert_eq!(result.session_wait, Some(1));
        assert!(result.keepers.iter().any(|k| k.1 == Some(late)));
        case.late_boundary(Phase::FinalAssertions, Boundary::End);
        case.late_boundary(Phase::Done, Boundary::Begin);
        case.late_boundary(Phase::Done, Boundary::End);
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

#[test]
fn keeper_abort_no_application_requires_full_receipt() {
    let proof = Completion {
        application: AppDisposition::NotStarted,
        session_wait: Some(0),
        broker_terminal: true,
        final_census: true,
        drained: true,
    };
    assert!(matches!(
        proof.status(),
        transport::channel_server::ChildStatus::Reaped { code: None }
    ));
}

#[test]
fn keeper_abort_cannot_follow_admit_or_fabricate_status() {
    let mut decision = AdmissionDecision::Pending;
    decision.commit(AdmissionDecision::Admit).unwrap();
    assert!(decision.commit(AdmissionDecision::Abort).is_err());
    let mut app = AppDisposition::Pending;
    assert!(app.not_started(decision, false).is_err());
    assert_eq!(app, AppDisposition::Pending);
    let mut decision = AdmissionDecision::Pending;
    decision.commit(AdmissionDecision::Abort).unwrap();
    assert!(decision.commit(AdmissionDecision::Admit).is_err());
    assert!(app.not_started(decision, true).is_err());
    app.not_started(decision, false).unwrap();
    assert_eq!(app.status(), None);
    assert!(app.not_started(decision, false).is_err());
    let mut waited = AppDisposition::Waited(37);
    assert!(waited.not_started(decision, false).is_err());
    assert_eq!(waited.status(), Some(37));
}

#[test]
fn keeper_cancel_keeps_progress_separate_from_custody_loss() {
    // A cancellation asks for an admission outcome. It provides none of the
    // independent receipts and must never synthesize an application exit code.
    let mut decision = AdmissionDecision::Pending;
    let requested = AdmissionDecision::Abort;
    assert_eq!(requested, AdmissionDecision::Abort);
    decision.commit(requested).unwrap();
    for _ in 0..3 {
        assert!(decision.commit(AdmissionDecision::Admit).is_err());
    }
    let mut proof = Completion::default();
    proof.application.not_started(decision, false).unwrap();
    assert!(matches!(
        proof.status(),
        transport::channel_server::ChildStatus::Running
    ));
    assert_eq!(proof.application.status(), None);
    assert!(proof.application.settled());
    for missing in 0..4 {
        let proof = Completion {
            application: AppDisposition::NotStarted,
            session_wait: if missing == 0 { None } else { Some(0) },
            broker_terminal: missing != 1,
            final_census: missing != 2,
            drained: missing != 3,
        };
        assert!(matches!(
            proof.status(),
            transport::channel_server::ChildStatus::Running
        ));
    }
}

#[cfg(target_os = "macos")]
#[test]
fn keeper_native_cancel_before_admit_no_application() {
    native_fixture::cancel_no_application();
}

#[test]
fn keeper_abort_frames_require_zero_fields_and_exact_sequence() {
    for operation in [Operation::AbortBeforeAdmit, Operation::AppNotStarted] {
        let instance = [77; 16];
        let mut decoder = Decoder::new(instance);
        let frame = Frame {
            operation,
            fields: [0; 4],
        };
        assert_eq!(decoder.feed(&encode(instance, 1, frame)), Ok(Some(frame)));
        assert!(decoder.feed(&encode(instance, 1, frame)).is_err());
        for index in 0..4 {
            let mut bad = frame;
            bad.fields[index] = 1;
            let mut decoder = Decoder::new(instance);
            assert!(decoder.feed(&encode(instance, 1, bad)).is_err());
            assert!(decoder.feed(&encode(instance, 1, frame)).is_err());
        }
    }
}

#[test]
fn keeper_expired_pending_admission_requests_abort() {
    assert_eq!(
        AdmissionDecision::Pending.pending(true, false, true, true),
        PendingAdmission::Abort
    );
    assert_eq!(
        AdmissionDecision::Pending.pending(true, false, false, true),
        PendingAdmission::GuardedAdmit
    );
    assert_eq!(
        AdmissionDecision::Pending.pending(true, true, false, true),
        PendingAdmission::Abort
    );
    assert_eq!(
        AdmissionDecision::Pending.pending(true, false, false, false),
        PendingAdmission::Abort
    );
    assert_eq!(
        AdmissionDecision::Admit.pending(true, true, true, false),
        PendingAdmission::None
    );
    assert_eq!(
        AdmissionDecision::Abort.pending(true, false, false, true),
        PendingAdmission::None
    );
    assert_eq!(
        AdmissionDecision::Pending.pending(false, false, true, true),
        PendingAdmission::None
    );
}

#[test]
fn keeper_fixture_gate_holds_ready_completion_until_release() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };
    use std::time::{Duration, Instant};
    // Exercise the same gate method used by the real macOS driver for BOTH
    // orderings, with a Ready result poised to complete after the hold.
    for after_admit in [false, true] {
        let end = Instant::now() + Duration::from_secs(60);
        let gate = Arc::new(FixtureAdmissionGate::new(after_admit));
        let core = Arc::new(Mutex::new(()));
        let complete = Arc::new(AtomicBool::new(false));
        let (driver_gate, driver_core, driver_complete) =
            (Arc::clone(&gate), Arc::clone(&core), Arc::clone(&complete));
        let worker = std::thread::spawn(move || {
            let ready = super::keeper_pty::Startup::Ready;
            {
                let _core = driver_core.lock().unwrap();
                assert_eq!(driver_gate.after_admit(), after_admit);
                assert!(driver_gate.pause());
                assert!(driver_gate.requested());
                assert!(
                    !driver_gate.reached(),
                    "Core request was published as a driver arrival"
                );
            }
            assert!(driver_gate.hold_until_release(end));
            assert!(matches!(ready, super::keeper_pty::Startup::Ready));
            driver_complete.store(true, Ordering::SeqCst);
        });
        while !gate.reached() {
            assert!(Instant::now() < end);
            assert!(
                !complete.load(Ordering::SeqCst),
                "Ready escaped before arrival acknowledgement"
            );
            std::thread::yield_now();
        }
        assert!(
            core.try_lock().is_ok(),
            "arrival acknowledged while Core remained locked"
        );
        while gate.held_polls() < 3 {
            assert!(Instant::now() < end);
            assert!(
                !complete.load(Ordering::SeqCst),
                "Ready escaped a held gate"
            );
            std::thread::yield_now();
        }
        assert!(!worker.is_finished());
        assert!(!complete.load(Ordering::SeqCst));
        gate.release();
        worker.join().unwrap();
        assert!(complete.load(Ordering::SeqCst));
    }
}

#[test]
fn keeper_late_diag_phase_boundaries_are_closed_and_distinct() {
    use late_diagnostics::*;
    let mut labels = std::collections::HashSet::new();
    for phase in Phase::ALL {
        assert!(labels.insert(phase.label()));
        let mut state = State::new();
        state.phase = phase;
        state.boundary = Boundary::Begin;
        assert!(state.line(true, None, None).contains("boundary=begin"));
        state.boundary = Boundary::End;
        assert!(state.line(true, None, None).contains("boundary=end"));
    }
    assert_eq!(labels.len(), 13);
    assert!(labels.contains("session_observed"));
}
#[test]
fn keeper_late_diag_absence_failure_and_poll_are_not_success() {
    use late_diagnostics::*;
    let mut state = State::new();
    let absent = state.line(false, None, None);
    assert!(absent.contains("controller_instant_before_end=false"));
    assert!(absent.contains("snapshot_available=false"));
    assert!(absent.contains("app_status=None"));
    assert!(absent.contains("last_poll=not_polled"));
    assert!(absent.contains("last_s_killed=unobserved"));
    assert!(absent.contains("reader=absent"));
    state.s_killed = Gate::Refused;
    state.poll = Poll::Unknown;
    let failed = state.line(false, None, None);
    assert!(failed.contains("last_s_killed=refused"));
    assert!(failed.contains("last_poll=unknown"));
    state.s_killed = Gate::Valid;
    state.poll = Poll::Reaped(Some(37));
    let available = state.line(
        true,
        Some(Snapshot::default()),
        Some(Io {
            eof: false,
            reader: Worker::Running,
            writer: Worker::Finished,
        }),
    );
    assert!(available.contains("snapshot_available=true"));
    assert!(available.contains("last_s_killed=valid"));
    assert!(available.contains("last_poll=reaped last_code=Some(37)"));
    assert!(available.contains("reader=running writer=finished"));
    assert!(state
        .line(
            true,
            None,
            Some(Io {
                eof: false,
                reader: Worker::Absent,
                writer: Worker::Absent
            })
        )
        .contains("reader=absent writer=absent"));
    for gate in [
        Gate::Unobserved,
        Gate::Missing,
        Gate::Refused,
        Gate::Mismatch,
        Gate::Readable,
        Gate::Valid,
        Gate::Written,
    ] {
        assert!(!gate.label().is_empty());
    }
    for poll in [
        Poll::NotPolled,
        Poll::Running,
        Poll::WaitingWorkers,
        Poll::Reaped(None),
        Poll::Unknown,
    ] {
        state.poll = poll;
        assert!(state.line(true, None, None).contains(poll.label()));
    }
    state.boundary = Boundary::Checkpoint;
    assert!(state.line(true, None, None).contains("boundary=checkpoint"));
    state.boundary = Boundary::Failure;
    assert!(state.line(true, None, None).contains("boundary=failure"));
}
#[test]
fn keeper_late_diag_extreme_scalars_remain_bounded_private_ascii() {
    use late_diagnostics::*;
    let state = State::new();
    let snapshot = Snapshot {
        app_status: Some(i32::MIN),
        session_status: Some(i32::MAX),
        session_wait: Some(i32::MIN),
        broker_parent: Some(i32::MAX),
        keepers: usize::MAX,
        ..Snapshot::default()
    };
    let line = state.line(false, Some(snapshot), None);
    assert!(line.starts_with("keeper223 late_diag "));
    assert!(line.is_ascii() && !line.contains(['\n', '\r']) && line.len() <= 2048);
    assert!(line.contains("app_status=Some(-2147483648)"));
    assert!(line.contains("session_status=Some(2147483647)"));
    assert!(line.contains(&format!("keepers=Some({})", usize::MAX)));
}

#[test]
fn keeper_late_diag_failed_writer_does_not_block_continuation() {
    struct Refused;
    impl std::io::Write for Refused {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut continued = false;
    let mut cleanup = || {
        late_diagnostics::emit(&mut Refused, format_args!("keeper223 late_diag refused"));
        continued = true;
    };
    cleanup();
    assert!(continued);
    let mut bytes = Vec::new();
    late_diagnostics::emit(
        &mut bytes,
        format_args!("keeper223 late_diag {}", "checkpoint"),
    );
    assert_eq!(bytes, b"keeper223 late_diag checkpoint\n");
}
