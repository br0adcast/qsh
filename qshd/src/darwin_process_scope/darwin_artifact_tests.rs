//! Fixed extracted-pair fixture. Portable controls are not native execution proof.
use std::collections::BTreeSet;

#[derive(Default)]
struct Custody {
    started: BTreeSet<u32>,
    waited: BTreeSet<u32>,
    open: bool,
    bound: bool,
    actor_exit: bool,
    io_joined: bool,
    daemon_exit: Option<i32>,
    client_exit: Option<i32>,
    rescue: bool,
    cleanup_failed: bool,
}
impl Custody {
    fn start(&mut self, id: u32) -> Result<(), &'static str> {
        if !self.started.insert(id) {
            return Err("duplicate child");
        }
        Ok(())
    }
    fn wait(&mut self, id: u32) -> Result<(), &'static str> {
        if !self.started.contains(&id) || !self.waited.insert(id) {
            return Err("unowned wait");
        }
        Ok(())
    }
    fn settled(&self) -> bool {
        !self.started.is_empty()
            && self.started == self.waited
            && self.io_joined
            && self.daemon_exit == Some(0)
            && !self.rescue
            && !self.cleanup_failed
            && (!self.open || (self.bound && self.actor_exit))
    }
    fn positive(&self) -> bool {
        self.settled() && self.client_exit == Some(37)
    }
}

fn actor_session(pid: u32, actual_sid: i32) -> bool {
    pid > 0 && i32::try_from(pid) == Ok(actual_sid)
}

fn framed_digest(raw: &[u8]) -> Option<String> {
    raw.windows(71).find_map(|frame| {
        let value = frame.strip_prefix(b"digest:")?;
        value
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
            .then(|| String::from_utf8_lossy(value).into_owned())
    })
}
#[test]
fn darwin185_portable_digest_requires_observed_complete_frame() {
    assert!(framed_digest(b"EOF and exit37").is_none());
    assert!(framed_digest(format!("digest:{}", "a".repeat(63)).as_bytes()).is_none());
    assert!(framed_digest(format!("digest:{}", "g".repeat(64)).as_bytes()).is_none());
    assert_eq!(
        framed_digest(format!("digest:{}\r\n", "a".repeat(64)).as_bytes()),
        Some("a".repeat(64))
    );
}

#[test]
fn darwin185_portable_actual_session_and_sticky_cleanup_failure() {
    assert!(!actor_session(42, 41));
    assert!(!actor_session(0, 0));
    assert!(actor_session(42, 42));
    let mut owner = Custody::default();
    owner.start(1).unwrap();
    owner.wait(1).unwrap();
    owner.open = true;
    owner.bound = true;
    owner.actor_exit = true;
    owner.io_joined = true;
    owner.daemon_exit = Some(0);
    owner.client_exit = Some(37);
    assert!(owner.positive());
    owner.cleanup_failed = true;
    // Later normal EOF/waits/daemon0 cannot erase an earlier authority/IO error.
    owner.io_joined = true;
    owner.daemon_exit = Some(0);
    assert!(!owner.positive());
}

#[test]
fn darwin185_portable_open_debt_survives_absence_and_client_exit() {
    let mut owner = Custody::default();
    owner.start(1).unwrap();
    owner.open = true;
    owner.wait(1).unwrap();
    owner.client_exit = Some(37);
    owner.io_joined = true;
    owner.daemon_exit = Some(0);
    assert!(!owner.settled());
    owner.bound = true;
    assert!(!owner.settled());
    owner.actor_exit = true;
    assert!(owner.positive());
}
#[test]
fn darwin185_portable_incomplete_wait_io_shutdown_or_rescue_refuses() {
    let mut owner = Custody::default();
    owner.start(1).unwrap();
    owner.open = true;
    owner.bound = true;
    owner.actor_exit = true;
    owner.client_exit = Some(37);
    owner.daemon_exit = Some(0);
    owner.io_joined = true;
    assert!(!owner.positive());
    owner.wait(1).unwrap();
    assert!(owner.positive());
    owner.io_joined = false;
    assert!(!owner.positive());
    owner.io_joined = true;
    owner.daemon_exit = Some(1);
    assert!(!owner.positive());
    owner.daemon_exit = Some(0);
    owner.rescue = true;
    assert!(!owner.positive());
}
#[test]
fn darwin185_portable_wait_requires_unique_started_child() {
    let mut owner = Custody::default();
    assert!(owner.wait(1).is_err());
    owner.start(1).unwrap();
    assert!(owner.start(1).is_err());
    owner.wait(1).unwrap();
    assert!(owner.wait(1).is_err());
}

type FixtureResult<T> = std::result::Result<T, &'static str>;
const LIMIT: usize = 65536;
use std::{fs::File, io::Read, os::fd::AsRawFd};

fn insert_child<T, E>(
    children: &mut Vec<T>,
    child: std::result::Result<T, E>,
    index: &mut Option<usize>,
) -> std::result::Result<(), E> {
    children.push(child?);
    *index = Some(children.len() - 1);
    Ok(())
}

#[test]
fn darwin185_portable_failed_spawn_preserves_existing_wait_owner() {
    use std::{
        os::unix::process::CommandExt,
        process::{Command, Stdio},
    };
    for pre_exec in [false, true] {
        let daemon = Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let mut children = vec![daemon];
        let mut index = None;
        let mut client = Command::new(if pre_exec {
            "/bin/sh"
        } else {
            "/nonexistent-qsh185-fixture"
        });
        if pre_exec {
            unsafe {
                client.pre_exec(|| Err(std::io::Error::from_raw_os_error(nix::libc::EIO)));
            }
        }
        assert!(insert_child(&mut children, client.spawn(), &mut index).is_err());
        let cleanup = std::panic::catch_unwind(|| index.is_none_or(|i| children[i].id() > 0));
        let waited = children[0].wait().unwrap();
        assert!(waited.success());
        assert!(cleanup.is_ok());
        assert!(index.is_none());
    }
}

struct Pump {
    file: File,
    data: Vec<u8>,
    eof: bool,
    pty: bool,
    overflow: bool,
}
impl Pump {
    fn new(file: File, pty: bool) -> FixtureResult<Self> {
        let fd = file.as_raw_fd();
        let flags = unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFL) };
        if flags < 0
            || unsafe { nix::libc::fcntl(fd, nix::libc::F_SETFL, flags | nix::libc::O_NONBLOCK) }
                < 0
        {
            return Err("IO");
        }
        Ok(Self {
            file,
            data: Vec::new(),
            eof: false,
            pty,
            overflow: false,
        })
    }
    fn drain(&mut self, exited: bool) -> FixtureResult<()> {
        if self.eof {
            return if self.overflow { Err("IO") } else { Ok(()) };
        }
        loop {
            let mut chunk = [0; 4096];
            match self.file.read(&mut chunk) {
                Ok(0) => {
                    self.eof = true;
                    return if self.overflow { Err("IO") } else { Ok(()) };
                }
                Ok(n) => {
                    if !self.overflow {
                        let retained = n.min(LIMIT.saturating_sub(self.data.len()));
                        let mut line = self
                            .data
                            .rsplit(|byte| *byte == b'\n')
                            .next()
                            .map_or(0, |line| line.len());
                        for &byte in &chunk[..retained] {
                            if byte == b'\n' {
                                line = 0;
                            } else if line == 4096 {
                                self.overflow = true;
                                break;
                            } else {
                                line += 1;
                            }
                            self.data.push(byte);
                        }
                        self.overflow |= retained < n;
                    }
                    // After overflow each call discards at most one real read;
                    // future calls still observe EOF and cannot clear failure.
                    if self.overflow {
                        return Err("IO");
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return if self.overflow { Err("IO") } else { Ok(()) }
                }
                Err(e) if self.pty && exited && e.raw_os_error() == Some(nix::libc::EIO) => {
                    self.eof = true;
                    return if self.overflow { Err("IO") } else { Ok(()) };
                }
                Err(_) => return Err("IO"),
            }
        }
    }
}

#[test]
fn darwin185_portable_repeated_overflow_drain_retains_cap_and_observes_eof() {
    use std::{
        io::Write,
        os::{
            fd::{FromRawFd, IntoRawFd},
            unix::net::UnixStream,
        },
    };
    for (initial, cap) in [(vec![b'\n'; LIMIT], LIMIT), (vec![b'x'; 4096], 4096)] {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        let mut pump =
            Pump::new(unsafe { File::from_raw_fd(reader.into_raw_fd()) }, false).unwrap();
        pump.data = initial;
        for _ in 0..4 {
            writer.write_all(&[b'x'; 4096]).unwrap();
            assert!(pump.drain(false).is_err());
            assert!(pump.data.len() <= cap);
            assert!(!pump.eof);
        }
        drop(writer);
        assert!(pump.drain(false).is_err());
        assert!(pump.eof);
        assert!(pump.data.len() <= cap);
        assert!(pump.drain(false).is_err());
    }
}

#[cfg(target_os = "macos")]
mod native {
    use super::{Custody, Pump};
    use crate::darwin_process_scope::{
        native::{NativeOps, Token, Watch},
        Class, Ops,
    };
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        net::UdpSocket,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{
                fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
                net::{UnixListener, UnixStream},
                process::CommandExt,
            },
        },
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        time::{Duration, Instant},
    };

    const ACTOR: &str =
        "darwin_process_scope::darwin_artifact_tests::native::darwin185_archive_actor";
    type Result<T> = std::result::Result<T, &'static str>;
    fn sha(raw: &[u8]) -> String {
        format!("{:x}", Sha256::digest(raw))
    }
    fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
        value[key].as_str().ok_or("INPUT")
    }
    fn bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| "INPUT")?;
        if !file.metadata().map_err(|_| "INPUT")?.is_file() {
            return Err("INPUT");
        }
        let mut raw = Vec::new();
        file.take((limit + 1) as u64)
            .read_to_end(&mut raw)
            .map_err(|_| "INPUT")?;
        if raw.is_empty() || raw.len() > limit {
            return Err("INPUT");
        }
        Ok(raw)
    }
    fn write_json(path: &Path, value: &Value) -> Result<()> {
        let mut raw = serde_json::to_vec(value).map_err(|_| "OUTPUT")?;
        raw.push(b'\n');
        if raw.len() > 16384 {
            return Err("OUTPUT");
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| "OUTPUT")?;
        file.write_all(&raw).map_err(|_| "OUTPUT")
    }
    fn request() -> Result<(Value, PathBuf)> {
        let path = PathBuf::from(std::env::var_os("QSH_DARWIN185_REQUEST").ok_or("INPUT")?);
        let raw = bounded(&path, 16384)?;
        let value: Value = serde_json::from_slice(&raw).map_err(|_| "INPUT")?;
        let keys = [
            "schema",
            "prepared",
            "prepared_sha256",
            "source_commit",
            "harness_sha256",
            "client",
            "daemon",
            "directory",
        ];
        let obj = value.as_object().ok_or("INPUT")?;
        if obj.len() != keys.len()
            || !keys.iter().all(|key| obj.contains_key(*key))
            || value["schema"] != 1
        {
            return Err("INPUT");
        }
        let directory = PathBuf::from(text(&value, "directory")?);
        if !directory.is_absolute()
            || directory.canonicalize().map_err(|_| "INPUT")? != directory
            || Some(directory.as_path()) != path.parent()
        {
            return Err("INPUT");
        }
        let info = fs::symlink_metadata(&directory).map_err(|_| "INPUT")?;
        if !info.is_dir()
            || info.uid() != unsafe { nix::libc::geteuid() }
            || info.mode() & 0o777 != 0o700
        {
            return Err("INPUT");
        }
        let mut prepared = serde_json::to_vec(&value["prepared"]).map_err(|_| "INPUT")?;
        prepared.push(b'\n');
        if sha(&prepared) != text(&value, "prepared_sha256")?
            || value["prepared"]["source_commit"] != value["source_commit"]
        {
            return Err("INPUT");
        }
        let exe = std::env::current_exe().map_err(|_| "INPUT")?;
        if sha(&bounded(&exe, 256 * 1024 * 1024)?) != text(&value, "harness_sha256")? {
            return Err("INPUT");
        }
        for (key, name) in [("client", "qsh"), ("daemon", "qshd")] {
            let path = PathBuf::from(text(&value, key)?);
            if !path.is_absolute()
                || path.canonicalize().map_err(|_| "INPUT")? != path
                || path.file_name().and_then(|v| v.to_str()) != Some(name)
            {
                return Err("INPUT");
            }
            let info = fs::symlink_metadata(&path).map_err(|_| "INPUT")?;
            if !info.is_file()
                || info.nlink() != 1
                || info.mode() & 0o777 != 0o700
                || info.uid() != unsafe { nix::libc::geteuid() }
            {
                return Err("INPUT");
            }
            if sha(&bounded(&path, 256 * 1024 * 1024)?)
                != value["prepared"]["binaries"][name]["sha256"]
            {
                return Err("INPUT");
            }
        }
        Ok((value, directory))
    }
    fn monotonic_ms() -> Result<u64> {
        let mut time = nix::libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        if unsafe { nix::libc::clock_gettime(nix::libc::CLOCK_MONOTONIC, &mut time) } != 0 {
            return Err("DEADLINE");
        }
        Ok(time.tv_sec as u64 * 1000 + time.tv_nsec as u64 / 1_000_000)
    }
    fn sysctl(name: &std::ffi::CStr) -> Result<String> {
        let mut data = [0u8; 512];
        let mut size = data.len();
        if unsafe {
            nix::libc::sysctlbyname(
                name.as_ptr(),
                data.as_mut_ptr().cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        } != 0
            || size == 0
            || size > data.len()
        {
            return Err("HOST");
        }
        std::str::from_utf8(&data[..size.saturating_sub(1)])
            .map(str::to_owned)
            .map_err(|_| "HOST")
    }
    fn host(target: &str) -> Result<Value> {
        super::super::native::prepare().map_err(|_| "HOST")?;
        if !super::super::native::modern_signal_available() {
            return Err("HOST");
        }
        let mut translated = 0i32;
        let mut size = std::mem::size_of_val(&translated);
        let code = unsafe {
            nix::libc::sysctlbyname(
                c"sysctl.proc_translated".as_ptr(),
                (&mut translated as *mut i32).cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if (code != 0 && std::io::Error::last_os_error().raw_os_error() != Some(nix::libc::ENOENT))
            || (code == 0 && translated != 0)
        {
            return Err("HOST");
        }
        let arch = match std::env::consts::ARCH {
            "aarch64" if target == "aarch64-apple-darwin" => "arm64",
            "x86_64" if target == "x86_64-apple-darwin" => "x86_64",
            _ => return Err("HOST"),
        };
        let version = sysctl(c"kern.osproductversion")?;
        if version.split('.').next() != Some("15") {
            return Err("HOST");
        }
        Ok(
            json!({"arch":arch,"darwin_release":sysctl(c"kern.osrelease")?,"os_version":version,
            "os_build":sysctl(c"kern.osversion")?,"kernel_version":sysctl(c"kern.version")?,"execution":"native"}),
        )
    }
    // Same ABI as native.c's SDK-asserted signal_fn: audit_token_t* and int,
    // returning int (0 success, errno on failure). Token is the repr(C) eight
    // u32 object acquired by NativeOps, passed by address without reconstruction.
    fn term(token: &mut Token) -> Result<()> {
        assert_eq!(std::mem::size_of::<Token>(), 32);
        let library = unsafe {
            nix::libc::dlopen(
                c"/usr/lib/libproc.dylib".as_ptr(),
                nix::libc::RTLD_LAZY | nix::libc::RTLD_LOCAL,
            )
        };
        if library.is_null() {
            return Err("IDENTITY");
        }
        let symbol = unsafe { nix::libc::dlsym(library, c"proc_signal_with_audittoken".as_ptr()) };
        if symbol.is_null() {
            unsafe { nix::libc::dlclose(library) };
            return Err("IDENTITY");
        }
        let signal: unsafe extern "C" fn(*mut Token, i32) -> i32 =
            unsafe { std::mem::transmute(symbol) };
        let code = unsafe { signal(token, nix::libc::SIGTERM) };
        unsafe { nix::libc::dlclose(library) };
        if code == 0 {
            Ok(())
        } else {
            Err("DAEMON_EXIT")
        }
    }
    struct Bound {
        token: Token,
        watch: Watch,
    }
    fn bind(pid: u32, cookie: u64, actor: bool) -> Result<Bound> {
        let mut ops = NativeOps;
        let process = ops
            .classify(i32::try_from(pid).map_err(|_| "IDENTITY")?)
            .map_err(|_| "IDENTITY")?;
        let Class::Session(sid) = process.class else {
            return Err("IDENTITY");
        };
        if actor && !super::actor_session(pid, sid) {
            return Err("IDENTITY");
        }
        let token = ops
            .acquire_signal_token(process.identity, sid)
            .map_err(|_| "IDENTITY")?;
        let watch = ops.bind_exit(process, cookie).map_err(|_| "IDENTITY")?;
        Ok(Bound {
            token: token.handle,
            watch: watch.handle,
        })
    }
    fn observed(bound: &mut Bound) -> Result<bool> {
        NativeOps
            .observe_exit(&mut bound.watch)
            .map(|event| event.is_some_and(|e| e.process_filter && e.note_exit && !e.error))
            .map_err(|_| "IDENTITY")
    }
    fn isolated(command: &mut Command, home: &Path) {
        command
            .env("HOME", home)
            .env("XDG_CACHE_HOME", home.join("cache"))
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("HISTFILE", "/dev/null")
            .env_remove("SSH_AUTH_SOCK")
            .env_remove("SSH_AGENT_PID");
    }
    struct Direct {
        ledger_id: u32,
        child: Child,
        status: Option<i32>,
    }
    impl Direct {
        fn spawn(command: &mut Command, custody: &mut Custody) -> Result<Self> {
            // A logical spawn ordinal is independent of recyclable OS PIDs.
            // Resolve every fallible ledger admission before creating the child.
            let ledger_id = u32::try_from(custody.started.len() + 1).map_err(|_| "CUSTODY")?;
            if ledger_id > 32 || custody.started.contains(&ledger_id) {
                return Err("CUSTODY");
            }
            let child = command.spawn().map_err(|_| "START")?;
            custody.started.insert(ledger_id);
            Ok(Self {
                ledger_id,
                child,
                status: None,
            })
        }
        fn poll(&mut self, custody: &mut Custody) -> Result<Option<i32>> {
            if self.status.is_none() {
                if let Some(status) = self.child.try_wait().map_err(|_| "CUSTODY")? {
                    self.status = Some(status.code().unwrap_or(-1));
                    custody.wait(self.ledger_id)?;
                }
            }
            Ok(self.status)
        }
        fn rescue(&mut self, custody: &mut Custody) {
            if self.status.is_none() {
                custody.rescue = true;
                let _ = self.child.kill();
            }
        }
    }
    fn tick() -> Result<()> {
        // Bounded readiness wait; no timing delay establishes a protocol fact.
        if unsafe { nix::libc::poll(std::ptr::null_mut(), 0, 10) } < 0 {
            return Err("IO");
        }
        Ok(())
    }
    fn deadline(end: Instant, directory: &Path) -> Result<()> {
        if Instant::now() >= end {
            return Err("DEADLINE");
        }
        if directory.join("cancel").exists() {
            return Err("CANCELLED");
        }
        Ok(())
    }
    fn quote(path: &Path) -> Result<String> {
        let value = path.to_str().ok_or("INPUT")?;
        if value.contains(['\n', '\r']) {
            return Err("INPUT");
        }
        Ok(format!("'{}'", value.replace('\'', "'\\''")))
    }
    fn contains(raw: &[u8], needle: &[u8]) -> bool {
        raw.windows(needle.len()).any(|window| window == needle)
    }

    #[test]
    #[ignore = "internal fixed actor, invoked only by the private SHELL wrapper"]
    fn darwin185_archive_actor() {
        fn actor() -> Result<i32> {
            let (request, directory) = request()?;
            let mut stream =
                UnixStream::connect(directory.join("control")).map_err(|_| "CONNECT")?;
            let actor_end = std::str::from_utf8(&bounded(&directory.join("actor-deadline"), 32)?)
                .map_err(|_| "INPUT")?
                .parse::<u64>()
                .map_err(|_| "INPUT")?;
            let remaining = actor_end
                .checked_sub(monotonic_ms()?)
                .filter(|v| *v > 0)
                .ok_or("DEADLINE")?;
            stream
                .set_read_timeout(Some(Duration::from_millis(remaining)))
                .map_err(|_| "IO")?;
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .map_err(|_| "IO")?;
            let registration = json!({"pid":std::process::id(),"sid":unsafe{nix::libc::getsid(0)},
                "request_id":request["prepared"]["request_id"],"source_commit":request["source_commit"],"nonce":request["prepared"]["challenge"]});
            let mut raw = serde_json::to_vec(&registration).map_err(|_| "INPUT")?;
            raw.push(b'\n');
            stream.write_all(&raw).map_err(|_| "IO")?;
            let mut ack = [0];
            stream.read_exact(&mut ack).map_err(|_| "IO")?;
            if ack == *b"A" {
                return Ok(0);
            }
            if ack != *b"G" {
                return Err("INPUT");
            }
            // A fixed actor owns no descendants. Its own deadline is below the
            // enclosing run budget; no interactive user shell is accepted.
            let mut input = Vec::new();
            let mut stdin = std::io::stdin();
            loop {
                if monotonic_ms()? >= actor_end {
                    return Err("DEADLINE");
                }
                let mut fds = [
                    nix::libc::pollfd {
                        fd: 0,
                        events: nix::libc::POLLIN,
                        revents: 0,
                    },
                    nix::libc::pollfd {
                        fd: stream.as_raw_fd(),
                        events: nix::libc::POLLIN,
                        revents: 0,
                    },
                ];
                if unsafe { nix::libc::poll(fds.as_mut_ptr(), 2, 100) } < 0 {
                    return Err("IO");
                }
                if fds[1].revents != 0 {
                    return Err("CANCELLED");
                }
                if fds[0].revents != 0 {
                    let mut byte = [0];
                    stdin.read_exact(&mut byte).map_err(|_| "IO")?;
                    if byte == *b"\n" {
                        break;
                    }
                    input.push(byte[0]);
                    if input.len() > 4096 {
                        return Err("INPUT");
                    }
                }
            }
            if input != text(&request["prepared"], "challenge")?.as_bytes() {
                return Err("OUTPUT");
            }
            println!("digest:{}", sha(&input));
            std::io::stdout().flush().map_err(|_| "IO")?;
            Ok(37)
        }
        std::process::exit(actor().unwrap_or(81));
    }
    fn execute(fault: bool) -> Result<()> {
        let (request, directory) = request()?;
        let prepared = &request["prepared"];
        let host = host(text(prepared, "target")?)?;
        let end = Instant::now() + Duration::from_secs(55);
        fs::write(
            directory.join("actor-deadline"),
            (monotonic_ms()? + 45000).to_string(),
        )
        .map_err(|_| "START")?;
        let mut custody = Custody::default();
        let mut children: Vec<Direct> = Vec::new();
        let mut pumps: Vec<Pump> = Vec::new();
        let mut daemon_bound: Option<Bound> = None;
        let mut actor_bound: Option<Bound> = None;
        let mut actor: Option<UnixStream> = None;
        let mut daemon_index = None;
        let mut client_index = None;
        let mut daemon_term = false;
        let mut trusted = false;
        let mut sent = false;
        let mut fault_reached = false;
        let mut observed_digest = None;
        let body = (|| -> Result<()> {
            let client_home = directory.join("client");
            let daemon_home = directory.join("daemon");
            fs::create_dir(&client_home).map_err(|_| "START")?;
            fs::create_dir(&daemon_home).map_err(|_| "START")?;
            fs::set_permissions(&client_home, fs::Permissions::from_mode(0o700))
                .map_err(|_| "START")?;
            fs::set_permissions(&daemon_home, fs::Permissions::from_mode(0o700))
                .map_err(|_| "START")?;
            let key = directory.join("identity");
            let mut keygen = Command::new("/usr/bin/ssh-keygen");
            keygen
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(&key)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            isolated(&mut keygen, &client_home);
            children.push(Direct::spawn(&mut keygen, &mut custody)?);
            while children[0].poll(&mut custody)?.is_none() {
                deadline(end, &directory)?;
                tick()?;
            }
            if children[0].status != Some(0) {
                return Err("START");
            }
            let authorized = daemon_home.join("authorized_keys");
            fs::write(&authorized, bounded(&key.with_extension("pub"), 4096)?)
                .map_err(|_| "START")?;
            fs::set_permissions(&authorized, fs::Permissions::from_mode(0o600))
                .map_err(|_| "START")?;
            let listener = UnixListener::bind(directory.join("control")).map_err(|_| "START")?;
            listener.set_nonblocking(true).map_err(|_| "IO")?;
            let wrapper = directory.join("shell");
            let exe = std::env::current_exe().map_err(|_| "INPUT")?;
            let shell = format!(
                "#!/bin/sh\nexec {} --exact {} --ignored --nocapture --test-threads=1\n",
                quote(&exe)?,
                ACTOR
            );
            fs::write(&wrapper, shell).map_err(|_| "START")?;
            fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700))
                .map_err(|_| "START")?;
            let udp = UdpSocket::bind("127.0.0.1:0").map_err(|_| "START")?;
            let port = udp.local_addr().map_err(|_| "START")?.port().to_string();
            drop(udp);
            let mut server = Command::new(text(&request, "daemon")?);
            server
                .args(["serve", "--port", &port, "--authorized-keys"])
                .arg(&authorized)
                .arg("--host-key")
                .arg(daemon_home.join("host_key"))
                .env("SHELL", &wrapper)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            isolated(&mut server, &daemon_home);
            super::insert_child(
                &mut children,
                Direct::spawn(&mut server, &mut custody),
                &mut daemon_index,
            )?;
            let server = children.last_mut().ok_or("CUSTODY")?;
            daemon_bound = Some(bind(server.child.id(), 1, false)?);
            let stdout = server.child.stdout.take().ok_or("IO")?;
            let stderr = server.child.stderr.take().ok_or("IO")?;
            // ChildStdout/Err transfer their owned descriptors, without duplication.
            use std::os::fd::IntoRawFd;
            pumps.push(Pump::new(
                unsafe { File::from_raw_fd(stdout.into_raw_fd()) },
                false,
            )?);
            pumps.push(Pump::new(
                unsafe { File::from_raw_fd(stderr.into_raw_fd()) },
                false,
            )?);
            let fingerprint = loop {
                deadline(end, &directory)?;
                if children[daemon_index.ok_or("CUSTODY")?]
                    .poll(&mut custody)?
                    .is_some()
                {
                    return Err("CONNECT");
                }
                for pump in &mut pumps {
                    pump.drain(false)?;
                    if pump.eof {
                        return Err("CONNECT");
                    }
                }
                let data = std::str::from_utf8(&pumps[0].data).map_err(|_| "OUTPUT")?;
                let public = data
                    .lines()
                    .find_map(|line| line.strip_prefix("server-pubkey: "));
                let shown = data
                    .lines()
                    .find_map(|line| line.strip_prefix("host-key-fingerprint: "));
                if let (Some(public), Some(shown)) = (public, shown) {
                    if public.len() > 128 || shown.len() > 128 {
                        return Err("OUTPUT");
                    }
                    let raw = STANDARD.decode(public).map_err(|_| "OUTPUT")?;
                    if raw.len() != 32 {
                        return Err("OUTPUT");
                    }
                    let expected = format!(
                        "SHA256:{}",
                        STANDARD.encode(Sha256::digest(&raw)).trim_end_matches('=')
                    );
                    if shown != expected {
                        return Err("OUTPUT");
                    }
                    break expected;
                }
                tick()?;
            };
            let mut master = -1;
            let mut slave = -1;
            let mut geometry = nix::libc::winsize {
                ws_row: 24,
                ws_col: 80,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            if unsafe {
                nix::libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut geometry,
                )
            } != 0
            {
                return Err("START");
            }
            let master = unsafe { File::from_raw_fd(master) };
            let slave = unsafe { File::from_raw_fd(slave) };
            let mut client = Command::new(text(&request, "client")?);
            client
                .arg("-i")
                .arg(&key)
                .args(["-p", &port, "127.0.0.1,nossh"])
                .stdin(slave.try_clone().map_err(|_| "IO")?)
                .stdout(slave.try_clone().map_err(|_| "IO")?)
                .stderr(slave);
            isolated(&mut client, &client_home);
            unsafe {
                client.pre_exec(|| {
                    if nix::libc::setsid() < 0 || nix::libc::ioctl(0, nix::libc::TIOCSCTTY, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            // Opening the real client incurs command debt before registration.
            custody.open = true;
            super::insert_child(
                &mut children,
                Direct::spawn(&mut client, &mut custody),
                &mut client_index,
            )?;
            // Command retains the slave Stdio until dropped; EOF requires release.
            drop(client);
            pumps.push(Pump::new(master, true)?);
            let mut registration = Vec::new();
            let mut pending = Vec::new();
            let mut registered = false;
            loop {
                deadline(end, &directory)?;
                let app = children[client_index.ok_or("CUSTODY")?].poll(&mut custody)?;
                for pump in &mut pumps {
                    pump.drain(app.is_some())?;
                }
                if actor.is_none() {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stream.set_nonblocking(true).map_err(|_| "IO")?;
                            actor = Some(stream);
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(_) => return Err("CONNECT"),
                    }
                }
                if let Some(stream) = actor.as_mut() {
                    if !registered {
                        let mut chunk = [0; 1024];
                        match stream.read(&mut chunk) {
                            Ok(0) => return Err("IDENTITY"),
                            Ok(n) => registration.extend_from_slice(&chunk[..n]),
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                            Err(_) => return Err("IO"),
                        }
                        if registration.len() > 4096 {
                            return Err("INPUT");
                        }
                        if registration.ends_with(b"\n") {
                            let value: Value =
                                serde_json::from_slice(&registration).map_err(|_| "IDENTITY")?;
                            if value.as_object().map(|v| v.len()) != Some(5)
                                || value["source_commit"] != request["source_commit"]
                                || value["request_id"] != prepared["request_id"]
                                || value["nonce"] != prepared["challenge"]
                            {
                                return Err("IDENTITY");
                            }
                            let pid = u32::try_from(value["pid"].as_u64().ok_or("IDENTITY")?)
                                .map_err(|_| "IDENTITY")?;
                            if value["sid"].as_u64() != Some(u64::from(pid)) {
                                return Err("IDENTITY");
                            }
                            let bound = bind(pid, 2, true)?;
                            // Registration is only a candidate: classify, full-token
                            // acquisition and actual NOTE_EXIT binding precede ack.
                            actor_bound = Some(bound);
                            custody.bound = true;
                            registered = true;
                            if fault {
                                fault_reached = true;
                                return Err("CANCELLED");
                            }
                            stream.write_all(b"G").map_err(|_| "IO")?;
                        }
                    }
                }
                if !trusted
                    && contains(&pumps[2].data, b"Key fingerprint")
                    && contains(&pumps[2].data, fingerprint.as_bytes())
                {
                    pending.extend_from_slice(b"yes\n");
                    trusted = true;
                }
                if registered && !sent {
                    pending.extend_from_slice(text(prepared, "challenge")?.as_bytes());
                    pending.push(b'\n');
                    sent = true;
                }
                if !pending.is_empty() {
                    match pumps[2].file.write(&pending) {
                        Ok(0) => return Err("IO"),
                        Ok(n) => {
                            pending.drain(..n);
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(_) => return Err("IO"),
                    }
                }
                if let Some(bound) = actor_bound.as_mut() {
                    if observed(bound)? {
                        custody.actor_exit = true;
                    }
                }
                if let Some(code) = app {
                    custody.client_exit = Some(code);
                    if code != 37 || !trusted || !sent {
                        return Err("CLIENT_EXIT");
                    }
                    observed_digest = super::framed_digest(&pumps[2].data);
                    if observed_digest.as_deref() != Some(text(prepared, "expected_output_digest")?)
                    {
                        return Err("OUTPUT");
                    }
                    if custody.actor_exit && pumps[2].eof {
                        break;
                    }
                }
                tick()?;
            }
            Ok(())
        })();
        // Settlement always runs with the actual owned handles and single-thread
        // nonblocking pumps. Unknown cleanup retains the entire private fixture.
        let cleanup_end = Instant::now() + Duration::from_secs(20);
        let rescue_at = Instant::now() + Duration::from_secs(12);
        if body.is_err() {
            if let Some(stream) = actor.as_mut() {
                let _ = stream.write_all(b"A");
            }
        }
        loop {
            let mut io_ok = !custody.cleanup_failed;
            for (index, child) in children.iter_mut().enumerate() {
                if child.poll(&mut custody).is_err() {
                    io_ok = false;
                }
                if Some(index) == client_index {
                    custody.client_exit = child.status;
                }
                if Some(index) == daemon_index {
                    custody.daemon_exit = child.status;
                }
            }
            if let Some(bound) = actor_bound.as_mut() {
                match observed(bound) {
                    Ok(true) => custody.actor_exit = true,
                    Ok(false) => {}
                    Err(_) => io_ok = false,
                }
            }
            if !daemon_term && custody.actor_exit {
                if let Some(bound) = daemon_bound.as_mut() {
                    daemon_term = true;
                    if term(&mut bound.token).is_err() {
                        io_ok = false;
                    }
                }
            }
            // Before registration, retain Open debt. Normal daemon0 alone never
            // invents an actor exit; this conservative path cannot qualify.
            if !daemon_term && body.is_err() && actor_bound.is_none() {
                if let Some(bound) = daemon_bound.as_mut() {
                    daemon_term = true;
                    if term(&mut bound.token).is_err() {
                        io_ok = false;
                    }
                }
            }
            let client_exited = client_index.is_none_or(|i| children[i].status.is_some());
            for pump in &mut pumps {
                if pump.drain(client_exited).is_err() {
                    io_ok = false;
                }
            }
            custody.cleanup_failed |= !io_ok;
            custody.io_joined = !custody.cleanup_failed && pumps.iter().all(|pump| pump.eof);
            let waited = children.iter().all(|child| child.status.is_some());
            if waited && custody.io_joined {
                break;
            }
            if Instant::now() >= rescue_at {
                if let Some(bound) = actor_bound.as_ref() {
                    if !custody.actor_exit {
                        custody.rescue = true;
                        let _ = NativeOps.signal_exact(&bound.token, super::super::Signal::Kill);
                    }
                }
                for child in &mut children {
                    child.rescue(&mut custody);
                }
            }
            if Instant::now() >= cleanup_end {
                let _ = write_json(
                    &directory.join("unresolved.json"),
                    &json!({
                    "schema":1,"kind":"darwin-archive-unresolved","started":custody.started.len(),
                    "waited":custody.waited.len(),"bound":custody.bound,"actor_exit":custody.actor_exit,
                    "open_debt":custody.open && !(custody.bound && custody.actor_exit),
                    "io_joined":custody.io_joined,"cleanup_failed":custody.cleanup_failed,"rescue":custody.rescue}),
                );
                return Err("UNSETTLED");
            }
            if tick().is_err() {
                custody.cleanup_failed = true;
            }
        }
        if fault {
            if !fault_reached || !custody.settled() {
                return Err("FAILURE_CUSTODY");
            }
            return write_json(
                &directory.join("result.json"),
                &json!({"schema":1,"kind":"darwin-archive-controlled-failure",
                "prepared_sha256":request["prepared_sha256"],"bound":custody.bound,"actor_exit":custody.actor_exit,
                "daemon_exit":custody.daemon_exit,"waited":custody.started==custody.waited,"io_joined":custody.io_joined,
                "rescue":custody.rescue,"unresolved":0}),
            );
        }
        body?;
        if !custody.positive() {
            return Err("CUSTODY");
        }
        let mut result = prepared.as_object().ok_or("INPUT")?.clone();
        result.remove("challenge");
        result.remove("expected_output_digest");
        result.insert("kind".into(), json!("darwin-archive-smoke"));
        result.insert("prepared_sha256".into(), request["prepared_sha256"].clone());
        result.insert("host".into(), host);
        result.insert("status".into(), json!("passed"));
        result.insert("failure".into(), Value::Null);
        result.insert("client_exit".into(), json!(custody.client_exit));
        result.insert("daemon_exit".into(), json!(custody.daemon_exit));
        result.insert("output_digest".into(), json!(observed_digest));
        result.insert("ownership".into(),json!({"direct_children_started":custody.started.len(),"direct_children_waited":custody.waited.len(),
            "command_exit_observed":custody.actor_exit,"remaining_children":0,"unresolved_owners":0,"rescue_used":custody.rescue,
            "harness_io_joined":custody.io_joined,"daemon_shutdown_completed":custody.daemon_exit==Some(0)}));
        write_json(&directory.join("result.json"), &Value::Object(result))
    }
    #[test]
    #[ignore = "native exact extracted release pair; explicit producer invocation only"]
    fn darwin185_archive_authenticated_pair() {
        assert_eq!(execute(false), Ok(()));
    }
    #[test]
    #[ignore = "native bounded failure after actual actor/watch registration"]
    fn darwin185_archive_failure_after_registration() {
        assert_eq!(execute(true), Ok(()));
    }
}
