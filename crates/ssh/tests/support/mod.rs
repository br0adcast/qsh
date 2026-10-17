//! A private OpenSSH server for tests: its own directory, host key and
//! authorized_keys, no root. Sessions run with HISTFILE=/dev/null and a
//! private TMUX_TMPDIR, so neither the developer's shell history nor their
//! tmux server is touched.

#![allow(dead_code)]

pub mod fake_server;

use std::collections::VecDeque;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const SSHD: &str = "/usr/sbin/sshd";

/// `None` means "no sshd here and QSH_NO_SSHD=1 says that is fine": the
/// caller returns early after this printed SKIPPED. Without the variable a
/// missing sshd is a failure, so a skip is never silent.
pub fn sshd_or_skip() -> Option<()> {
    if Path::new(SSHD).exists() {
        return Some(());
    }
    if std::env::var("QSH_NO_SSHD").as_deref() == Ok("1") {
        eprintln!("SKIPPED: no sshd at {SSHD}");
        return None;
    }
    panic!("{SSHD} not found; install openssh-server or set QSH_NO_SSHD=1 to skip");
}

pub struct TestSshd {
    pub dir: tempfile::TempDir,
    pub port: u16,
    child: Child,
    first_host_pub: String,
}

#[derive(Default, Clone)]
pub struct SshdOptions {
    pub authorized_keys: Vec<String>,
    /// Host key types to generate, in the order sshd lists them; empty = ["ed25519"].
    pub host_key_types: Vec<&'static str>,
    pub max_auth_tries: Option<u32>,
    /// `AuthenticationMethods`, e.g. "publickey,publickey" for two keys.
    pub authentication_methods: Option<&'static str>,
    /// More `SetEnv` pairs for every session, after HISTFILE/TMUX_TMPDIR.
    /// Values are quoted for sshd_config, including paths with spaces.
    pub session_env: Vec<(String, String)>,
}

impl TestSshd {
    /// Starts sshd trusting `authorized_keys` (one OpenSSH public key line
    /// per entry). Retries on another port if the chosen one was taken.
    pub fn start(authorized_keys: &[String]) -> TestSshd {
        Self::start_with(SshdOptions {
            authorized_keys: authorized_keys.to_vec(),
            ..SshdOptions::default()
        })
    }

    /// `host_public_key_line()` stays the first host key's line;
    /// `host_public_key_line_of(kind)` gives any of them.
    pub fn start_with(opts: SshdOptions) -> TestSshd {
        let dir = tempfile::tempdir().expect("tempdir");
        let d = dir.path();
        let kinds = if opts.host_key_types.is_empty() {
            vec!["ed25519"]
        } else {
            opts.host_key_types.clone()
        };
        let host_keys: Vec<PathBuf> = kinds
            .iter()
            .map(|kind| {
                let path = d.join(format!("host_{kind}"));
                let bits = if *kind == "rsa" { "3072" } else { "0" };
                let ok = Command::new("ssh-keygen")
                    .args(["-q", "-t", kind, "-N", ""])
                    .args(if *kind == "rsa" {
                        vec!["-b", bits]
                    } else {
                        vec![]
                    })
                    .arg("-f")
                    .arg(&path)
                    .status()
                    .expect("ssh-keygen")
                    .success();
                assert!(ok, "ssh-keygen failed");
                path
            })
            .collect();
        std::fs::write(
            d.join("authorized_keys"),
            opts.authorized_keys.join("\n") + "\n",
        )
        .unwrap();
        std::fs::create_dir(d.join("tmux")).unwrap();
        // What tmux itself would create under TMUX_TMPDIR, made here so a
        // local `tmux -S` (see `tmux()`) can reach the same socket before
        // any session through sshd has run tmux. tmux insists on 0700.
        {
            use std::os::unix::fs::{DirBuilderExt, MetadataExt};
            let uid = std::fs::metadata(d).unwrap().uid();
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(d.join("tmux").join(format!("tmux-{uid}")))
                .unwrap();
        }
        for _ in 0..20 {
            let port = free_port();
            write_config(d, port, &host_keys, &opts);
            let mut child = Command::new(SSHD)
                .arg("-D")
                .arg("-f")
                .arg(d.join("sshd_config"))
                .arg("-E")
                .arg(d.join("sshd.log"))
                .stdin(Stdio::null())
                .spawn()
                .expect("spawn sshd");
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                if let Ok(Some(_)) = child.try_wait() {
                    break; // port taken or bad config: next port
                }
                if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                    return TestSshd {
                        dir,
                        port,
                        child,
                        first_host_pub: format!("host_{}.pub", kinds[0]),
                    };
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
        panic!("sshd did not start; see its log");
    }

    pub fn host_public_key_line(&self) -> String {
        std::fs::read_to_string(self.dir.path().join(&self.first_host_pub)).unwrap()
    }

    pub fn host_public_key_line_of(&self, kind: &str) -> String {
        std::fs::read_to_string(self.dir.path().join(format!("host_{kind}.pub"))).unwrap()
    }

    pub fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("sshd.log")).unwrap_or_default()
    }

    pub fn tmux_dir(&self) -> PathBuf {
        self.dir.path().join("tmux")
    }

    /// The socket of the private tmux server: where tmux puts it under
    /// `TMUX_TMPDIR` (`tmux-<uid>/default`), as sessions started through
    /// sshd find it.
    pub fn tmux_socket(&self) -> PathBuf {
        // The uid tmux uses is ours; the temp dir was created by us.
        use std::os::unix::fs::MetadataExt;
        let uid = std::fs::metadata(self.dir.path()).unwrap().uid();
        self.tmux_dir().join(format!("tmux-{uid}")).join("default")
    }

    /// A local `tmux` command bound to the private server only. `$TMUX`
    /// wins over `TMUX_TMPDIR`, so inside a developer's tmux a bare `tmux`
    /// would reach their own server; an explicit socket and no `$TMUX`
    /// cannot.
    ///
    /// `HISTFILE=/dev/null` too, on every call: the first command that
    /// reaches the private socket starts that tmux server, the server keeps
    /// the environment it started with, and every pane's shell inherits it.
    /// Without this those shells are the developer's own login shells, and
    /// whatever a test types into them (`echo IN'PUT'OK`) lands in the
    /// developer's real shell history when the server is killed. The sshd
    /// sessions get the same through `SetEnv` in the config below; this
    /// covers the server a test starts from outside sshd.
    pub fn tmux(&self) -> Command {
        let mut c = Command::new("tmux");
        c.env_remove("TMUX")
            .env("HISTFILE", "/dev/null")
            .env("TMUX_TMPDIR", self.tmux_dir())
            .arg("-S")
            .arg(self.tmux_socket());
        c
    }

    pub fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for TestSshd {
    fn drop(&mut self) {
        // The private tmux server, if a test started one.
        let _ = self
            .tmux()
            .arg("kill-server")
            .stderr(Stdio::null())
            .status();
        self.kill();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn write_config(d: &Path, port: u16, host_keys: &[PathBuf], opts: &SshdOptions) {
    let host_key_lines: String = host_keys
        .iter()
        .map(|k| format!("HostKey {}\n", k.display()))
        .collect();
    let max_tries = opts
        .max_auth_tries
        .map(|n| format!("MaxAuthTries {n}\n"))
        .unwrap_or_default()
        + &opts
            .authentication_methods
            .map(|m| format!("AuthenticationMethods {m}\n"))
            .unwrap_or_default();
    let more_env: String = opts
        .session_env
        .iter()
        .map(|(name, value)| format!(" {}", config_quote(&format!("{name}={value}"))))
        .collect();
    let cfg = format!(
        "Port {port}\nListenAddress 127.0.0.1\n{host_key_lines}{max_tries}PidFile {}\n\
         AuthorizedKeysFile {}\nStrictModes no\nUsePAM no\nPasswordAuthentication no\n\
         PubkeyAuthentication yes\nCompression yes\nLogLevel DEBUG1\nSubsystem sftp internal-sftp\n\
         SetEnv HISTFILE=/dev/null TMUX_TMPDIR={}{more_env}\n",
        d.join("sshd.pid").display(),
        d.join("authorized_keys").display(),
        d.join("tmux").display(),
    );
    std::fs::write(d.join("sshd_config"), cfg).unwrap();
}

fn config_quote(value: &str) -> String {
    assert!(!value.contains(['\n', '\r', '\0']));
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Establish the SFTP sandbox with an independent OpenSSH marker round trip.
/// Both remote paths are absolute and contained in this server's TempDir.
pub fn sftp_probe(sshd: &TestSshd, key: &Path) {
    use std::io::Write;
    let source = sshd.dir.path().join("probe-source");
    let remote = sshd.dir.path().join("probe-remote");
    let returned = sshd.dir.path().join("probe-returned");
    let marker = b"qsh SFTP sandbox\0\xff\n";
    std::fs::write(&source, marker).unwrap();
    let mut child = Command::new("sftp")
        .args([
            "-q",
            "-F",
            "/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "IdentityAgent=none",
            "-o",
            "IdentitiesOnly=yes",
            "-i",
        ])
        .arg(key)
        .arg("-P")
        .arg(sshd.port.to_string())
        .args(["-b", "-", "127.0.0.1"])
        .env("HISTFILE", "/dev/null")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("SFTP probe");
    write!(
        child.stdin.take().unwrap(),
        "put \"{}\" \"{}\"\nget \"{}\" \"{}\"\n",
        source.display(),
        remote.display(),
        remote.display(),
        returned.display()
    )
    .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "SFTP probe: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(std::fs::read(&remote).unwrap(), marker);
    assert_eq!(std::fs::read(&returned).unwrap(), marker);
}

/// A software P-256 key for external SSH signing tests.
pub struct SoftSigner(pub p256::ecdsa::SigningKey);

impl SoftSigner {
    pub fn random() -> Self {
        SoftSigner(p256::ecdsa::SigningKey::random(&mut rand_core::OsRng))
    }

    pub fn public_wire(&self) -> Vec<u8> {
        let point = self.0.verifying_key().to_encoded_point(false);
        let mut out = Vec::new();
        for part in [&b"ecdsa-sha2-nistp256"[..], b"nistp256", point.as_bytes()] {
            out.extend_from_slice(&(part.len() as u32).to_be_bytes());
            out.extend_from_slice(part);
        }
        out
    }

    pub fn authorized_line(&self) -> String {
        use base64::Engine;
        format!(
            "ecdsa-sha2-nistp256 {} test",
            base64::engine::general_purpose::STANDARD.encode(self.public_wire())
        )
    }
}

impl ssh::ExternalSigner for SoftSigner {
    fn public_key(&self) -> Result<Vec<u8>, String> {
        Ok(self.public_wire())
    }
    fn sign_ssh(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        use p256::ecdsa::signature::Signer;
        let sig: p256::ecdsa::Signature = self.0.sign(data);
        let sig = ssh_key::Signature::try_from(&sig).map_err(|e| e.to_string())?;
        sshauth::record::encode_signature(&sig).map_err(|e| e.to_string())
    }
}

/// A fresh OpenSSH-format private key of `kind` ("ed25519" / "ecdsa"),
/// generated by ssh-keygen: (PEM text, authorized_keys line).
pub fn keygen(kind: &str, dir: &Path) -> (String, String) {
    let (path, pub_line) = keygen_file(kind, dir);
    (std::fs::read_to_string(&path).unwrap(), pub_line)
}

/// Like `keygen`, but gives the key file's path: (path, authorized_keys line).
pub fn keygen_file(kind: &str, dir: &Path) -> (PathBuf, String) {
    let path = dir.join(format!("client_{kind}"));
    run_keygen(kind, &path, "");
    let pub_line = std::fs::read_to_string(path.with_extension("pub")).unwrap();
    (path, pub_line)
}

/// A key file of `kind` locked with `pass`: (path, authorized_keys line).
pub fn keygen_with_passphrase(kind: &str, dir: &Path, pass: &str) -> (PathBuf, String) {
    let path = dir.join(format!("client_{kind}_locked"));
    run_keygen(kind, &path, pass);
    let pub_line = std::fs::read_to_string(path.with_extension("pub")).unwrap();
    (path, pub_line)
}

fn run_keygen(kind: &str, path: &Path, pass: &str) {
    let ok = Command::new("ssh-keygen")
        .args(["-q", "-t", kind, "-N", pass])
        .arg("-f")
        .arg(path)
        .status()
        .unwrap()
        .success();
    assert!(ok, "ssh-keygen failed");
}

/// A private ssh-agent on a socket in its own temp dir. Never the user's:
/// nothing here reads `SSH_AUTH_SOCK`, and `ssh-add` is pointed at this
/// socket only.
pub struct TestAgent {
    dir: tempfile::TempDir,
    child: Child,
}

impl TestAgent {
    pub fn start() -> TestAgent {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("agent.sock");
        // -D: stay in the foreground, so the child we spawn is the agent itself.
        let mut child = Command::new("ssh-agent")
            .arg("-D")
            .arg("-a")
            .arg(&sock)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .expect("ssh-agent");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !sock.exists() {
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("ssh-agent did not start");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        TestAgent { dir, child }
    }

    pub fn socket(&self) -> PathBuf {
        self.dir.path().join("agent.sock")
    }

    pub fn add(&self, key: &Path) {
        let ok = Command::new("ssh-add")
            .env("SSH_AUTH_SOCK", self.socket())
            .env_remove("SSH_AGENT_PID")
            .arg("-q")
            .arg(key)
            .stdin(Stdio::null())
            .status()
            .unwrap()
            .success();
        assert!(ok, "ssh-add failed");
    }
}

impl Drop for TestAgent {
    fn drop(&mut self) {
        // Only the agent this test started, through its own child handle.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A prompter that counts its questions and answers from what it was given;
/// an exhausted queue, like an unset answer, is "no answer".
#[derive(Default)]
pub struct CountingPrompter {
    pub passphrase_asked: AtomicUsize,
    pub password_asked: AtomicUsize,
    pub kbd_asked: AtomicUsize,
    pub passphrases: Mutex<VecDeque<Option<String>>>,
    pub password: Option<String>,
    /// keyboard-interactive answers, one per prompt, taken in order.
    pub kbd: Mutex<VecDeque<String>>,
    /// Slept before every answer: a person taking their time.
    pub delay: Duration,
}

impl CountingPrompter {
    pub fn answering_passphrases(answers: &[&str]) -> Self {
        let answers: Vec<Option<&str>> = answers.iter().map(|a| Some(*a)).collect();
        Self::answering_passphrases_opt(&answers)
    }

    pub fn answering_passphrases_opt(answers: &[Option<&str>]) -> Self {
        CountingPrompter {
            passphrases: Mutex::new(answers.iter().map(|a| a.map(str::to_string)).collect()),
            ..CountingPrompter::default()
        }
    }

    pub fn answering_password(password: &str) -> Self {
        CountingPrompter {
            password: Some(password.to_string()),
            ..CountingPrompter::default()
        }
    }

    /// One answer per keyboard-interactive prompt, in the order asked.
    pub fn answering_kbd(answers: &[&str]) -> Self {
        CountingPrompter {
            kbd: Mutex::new(answers.iter().map(|a| a.to_string()).collect()),
            ..CountingPrompter::default()
        }
    }

    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    pub fn passphrase_asked(&self) -> usize {
        self.passphrase_asked.load(Ordering::SeqCst)
    }

    pub fn password_asked(&self) -> usize {
        self.password_asked.load(Ordering::SeqCst)
    }

    pub fn kbd_asked(&self) -> usize {
        self.kbd_asked.load(Ordering::SeqCst)
    }
}

impl ssh::AuthPrompter for CountingPrompter {
    fn passphrase(&self, _: &Path) -> Option<ssh::Zeroizing<String>> {
        std::thread::sleep(self.delay);
        self.passphrase_asked.fetch_add(1, Ordering::SeqCst);
        let next = self.passphrases.lock().unwrap().pop_front().flatten();
        next.map(ssh::Zeroizing::new)
    }

    fn password(&self, _: &str, _: &str) -> Option<ssh::Zeroizing<String>> {
        std::thread::sleep(self.delay);
        self.password_asked.fetch_add(1, Ordering::SeqCst);
        self.password.clone().map(ssh::Zeroizing::new)
    }

    fn keyboard_interactive(
        &self,
        _: &str,
        _: &str,
        prompts: &[ssh::Prompt],
    ) -> Option<Vec<ssh::Zeroizing<String>>> {
        std::thread::sleep(self.delay);
        self.kbd_asked.fetch_add(1, Ordering::SeqCst);
        let mut queue = self.kbd.lock().unwrap();
        if queue.is_empty() {
            return None;
        }
        let take = prompts.len().min(queue.len());
        Some(queue.drain(..take).map(ssh::Zeroizing::new).collect())
    }
}

/// The host key of a running TestSshd, in SSH wire format.
pub fn wire_of(pub_line: &str) -> Vec<u8> {
    use base64::Engine;
    let b64 = pub_line.split_whitespace().nth(1).unwrap();
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .unwrap()
}

/// A TCP relay in front of sshd that a test can cut, to lose the connection
/// the way a network does -- killing sshd would not: `sshd -D` serves each
/// connection from a forked child that outlives its parent.
pub struct Proxy {
    pub port: u16,
    cut: std::sync::Arc<std::sync::atomic::AtomicBool>,
    streams: std::sync::Arc<std::sync::Mutex<Vec<TcpStream>>>,
}

impl Proxy {
    pub fn start(target_port: u16) -> Proxy {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Mutex};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let cut = Arc::new(AtomicBool::new(false));
        let streams: Arc<Mutex<Vec<TcpStream>>> = Arc::new(Mutex::new(Vec::new()));
        let (c, st) = (Arc::clone(&cut), Arc::clone(&streams));
        std::thread::spawn(move || {
            for client in listener.incoming() {
                let Ok(client) = client else { return };
                if c.load(Ordering::SeqCst) {
                    return;
                }
                let server = TcpStream::connect(("127.0.0.1", target_port)).unwrap();
                st.lock().unwrap().push(client.try_clone().unwrap());
                st.lock().unwrap().push(server.try_clone().unwrap());
                for (mut from, mut to) in [
                    (client.try_clone().unwrap(), server.try_clone().unwrap()),
                    (server, client),
                ] {
                    std::thread::spawn(move || {
                        let _ = std::io::copy(&mut from, &mut to);
                        let _ = to.shutdown(std::net::Shutdown::Both);
                    });
                }
            }
        });
        Proxy { port, cut, streams }
    }

    /// Drop every relayed connection at once.
    pub fn cut(&self) {
        self.cut.store(true, std::sync::atomic::Ordering::SeqCst);
        for s in self.streams.lock().unwrap().iter() {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
    }
}

/// Events nobody listens to, for tests that only log in.
pub struct NullEvents;
impl ssh::SshEvents for NullEvents {
    fn on_channel(&self, _: client::channel::SubstrateEvent) {}
    fn on_closed(&self, _: String) {}
}

pub fn params(sshd: &TestSshd, known: Vec<Vec<u8>>) -> ssh::SshParams {
    ssh::SshParams {
        host: "127.0.0.1".into(),
        port: sshd.port,
        username: std::env::var("USER").expect("USER"),
        known_host_keys: known,
        connect_timeout: Duration::from_secs(5),
        keepalive_interval: Duration::from_secs(15),
        compression: true,
        tcp_nodelay: true,
        knock: Vec::new(),
    }
}
