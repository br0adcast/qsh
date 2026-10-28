//! Installation uses the real CLI, a controlling PTY and private SSH homes.
#[path = "support/releases.rs"]
#[allow(dead_code)]
mod releases;
mod support;
#[path = "../../crates/bringup/tests/support_home/mod.rs"]
mod support_home;

use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use support::*;
use support_home::Sandbox;

struct Screen(Arc<Mutex<Vec<u8>>>);
impl Screen {
    fn of(client: &Client) -> Self {
        let seen = Arc::new(Mutex::new(Vec::new()));
        drain_into(client.master.try_clone().unwrap(), seen.clone());
        Self(seen)
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
    fn wait(&self, needle: &str) {
        assert!(
            wait_until(|| self.text().contains(needle)),
            "missing {needle}: {}",
            self.text()
        );
    }
}
fn key(home: &Path) -> (PathBuf, String) {
    let key = ssh_key::PrivateKey::random(
        &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
        ssh_key::Algorithm::Ed25519,
    )
    .unwrap();
    let path = home.join("identity");
    std::fs::write(
        &path,
        key.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes(),
    )
    .unwrap();
    (path, key.public_key().to_openssh().unwrap())
}
fn trust(home: &Path, sb: &Sandbox) {
    let path = home.join(".ssh");
    std::fs::create_dir_all(&path).unwrap();
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path.join("known_hosts"))
        .unwrap();
    writeln!(
        file,
        "[127.0.0.1]:{} {}",
        sb.sshd.port,
        sb.sshd.host_public_key_line()
    )
    .unwrap();
}
fn address(sb: &Sandbox) -> String {
    format!("127.0.0.1:{},ssh={}", free_udp_port(), sb.sshd.port)
}
fn image_path(sb: &Sandbox) -> PathBuf {
    sb.cache().join(format!(
        "qshd-{}-{}",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::ARCH
    ))
}
fn seed(home: &Path) {
    let request = bringup::ImageRequest::new(
        bringup::Platform::from_uname("Linux", std::env::consts::ARCH).unwrap(),
        env!("CARGO_PKG_VERSION"),
    )
    .unwrap();
    releases::seed_release_cache(&home.join("qsh"), &request, &qshd_path());
}
fn start(home: &Path, key: &Path, addresses: &[String]) -> (Client, Screen) {
    let mut args = vec!["--verbose", "-i", key.to_str().unwrap()];
    args.extend(addresses.iter().map(String::as_str));
    let client = spawn_qsh(&args, home);
    let screen = Screen::of(&client);
    (client, screen)
}
#[test]
fn accept_installs_and_opens_shell() {
    let _serial = serialised();
    let home = tempfile::tempdir().unwrap();
    let (key, public) = key(home.path());
    let sb = Sandbox::start_with(&[public]);
    trust(home.path(), &sb);
    seed(home.path());
    let (mut client, screen) = start(home.path(), &key, &[address(&sb)]);
    screen.wait(&format!("Install qshd {}", env!("CARGO_PKG_VERSION")));
    assert!(screen
        .text()
        .contains(&format!("127.0.0.1:{}", sb.sshd.port)));
    let server_target = match std::env::consts::ARCH {
        "x86_64" => "x86_64-unknown-linux-musl",
        "aarch64" => "aarch64-unknown-linux-musl",
        other => panic!("unsupported test server architecture: {other}"),
    };
    assert!(screen.text().contains(server_target));
    assert!(screen.text().contains(image_path(&sb).to_str().unwrap()));
    client.master.write_all(b"yes\n").unwrap();
    screen.wait("Authorize SSH recovery");
    assert!(
        !screen.text().contains("Key fingerprint"),
        "{}",
        screen.text()
    );
    client.master.write_all(b"no\n").unwrap();
    client.type_line("echo INSTALL_'OK'");
    screen.wait("INSTALL_OK");
    assert!(image_path(&sb).is_file());
    screen.wait("Uploading qshd");
    let output = screen.text();
    let metadata = output
        .find("Checking release metadata")
        .expect("metadata wait is visible");
    let upload = output.find("Uploading qshd").unwrap();
    assert!(
        metadata < upload,
        "metadata phase precedes image upload: {output}"
    );
    assert!(output.contains("Ctrl-C cancels"));
    assert!(
        !output.contains("Downloading qshd"),
        "a cache hit has no archive transfer: {output}"
    );
    client.type_line("exit");
    assert!(wait_for_exit(&mut client.child).unwrap().success());
}
#[test]
fn enter_accepts_installation_and_opens_shell() {
    let _serial = serialised();
    let home = tempfile::tempdir().unwrap();
    let (key, public) = key(home.path());
    let sb = Sandbox::start_with(&[public]);
    trust(home.path(), &sb);
    seed(home.path());
    let (mut client, screen) = start(home.path(), &key, &[address(&sb)]);
    screen.wait(&format!("Install qshd {}", env!("CARGO_PKG_VERSION")));
    assert!(screen
        .text()
        .contains(&format!("127.0.0.1:{}", sb.sshd.port)));
    let server_target = match std::env::consts::ARCH {
        "x86_64" => "x86_64-unknown-linux-musl",
        "aarch64" => "aarch64-unknown-linux-musl",
        other => panic!("unsupported test server architecture: {other}"),
    };
    assert!(screen.text().contains(server_target));
    assert!(screen.text().contains(image_path(&sb).to_str().unwrap()));
    screen.wait("[Y/n]");
    assert!(screen.text().contains("  Source    GitHub Releases"));
    client.master.write_all(b"\n").unwrap();
    screen.wait("Authorize SSH recovery");
    assert!(
        !screen.text().contains("Key fingerprint"),
        "{}",
        screen.text()
    );
    client.master.write_all(b"no\n").unwrap();
    client.type_line("echo INSTALL_'OK'");
    screen.wait("INSTALL_OK");
    assert!(image_path(&sb).is_file());
    screen.wait("Uploading qshd");
    client.type_line("exit");
    assert!(wait_for_exit(&mut client.child).unwrap().success());
}
#[test]
fn decline_stops_the_entire_address_ladder() {
    let _serial = serialised();
    let home = tempfile::tempdir().unwrap();
    let (key, public) = key(home.path());
    let first = Sandbox::start_with(std::slice::from_ref(&public));
    let second = Sandbox::start_with(&[public]);
    trust(home.path(), &first);
    trust(home.path(), &second);
    let (mut client, screen) = start(home.path(), &key, &[address(&first), address(&second)]);
    screen.wait("Install qshd");
    client.master.write_all(b"no\n").unwrap();
    assert_eq!(wait_for_exit(&mut client.child).unwrap().code(), Some(1));
    screen.wait("qsh: daemon installation was declined");
    assert!(!screen
        .text()
        .contains(&format!("trying ssh:{}", second.sshd.port)));
    assert!(!image_path(&first).exists());
    assert!(!image_path(&second).exists());
    assert!(!home.path().join("qsh/releases").exists());
}
#[test]
fn eof_does_not_install() {
    let _serial = serialised();
    let home = tempfile::tempdir().unwrap();
    let (key, public) = key(home.path());
    let sb = Sandbox::start_with(&[public]);
    trust(home.path(), &sb);
    let (mut client, screen) = start(home.path(), &key, &[address(&sb)]);
    screen.wait("Install qshd");
    client.master.write_all(b"\x04").unwrap();
    assert_eq!(wait_for_exit(&mut client.child).unwrap().code(), Some(1));
    assert!(!image_path(&sb).exists());
    assert!(!home.path().join("qsh/releases").exists());
}
#[test]
fn approval_does_not_authorize_another_host() {
    let _serial = serialised();
    let home = tempfile::tempdir().unwrap();
    let (key, public) = key(home.path());
    let first = Sandbox::start_with(std::slice::from_ref(&public));
    let second = Sandbox::start_with(&[public]);
    // Fail remote verification after approval, forcing a separate SSH operation.
    first.fake_qshd(&first.home.path().join("bin/sha256sum"), "exit 1");
    trust(home.path(), &first);
    trust(home.path(), &second);
    seed(home.path());
    let (mut client, screen) = start(home.path(), &key, &[address(&first), address(&second)]);
    screen.wait("Install qshd");
    client.master.write_all(b"yes\n").unwrap();
    assert!(
        wait_until(|| screen.text().matches("Install qshd").count() == 2),
        "{}",
        screen.text()
    );
    assert!(!image_path(&second).exists());
    client.master.write_all(b"no\n").unwrap();
    assert_eq!(wait_for_exit(&mut client.child).unwrap().code(), Some(1));
}
#[test]
fn ctrl_c_during_install_restores_tty() {
    let _serial = serialised();
    let home = tempfile::tempdir().unwrap();
    let (key, public) = key(home.path());
    let sb = Sandbox::start_with(&[public]);
    trust(home.path(), &sb);
    seed(home.path());
    // Keep verification in flight, so Ctrl-C cancels an installation after approval.
    sb.fake_qshd(&sb.home.path().join("bin/sha256sum"), "exec /bin/sleep 30");
    let addr = address(&sb);
    let (mut client, slave) = spawn_qsh_on(&["-i", key.to_str().unwrap(), &addr], home.path());
    let original = nix::sys::termios::tcgetattr(&slave).unwrap();
    let screen = Screen::of(&client);
    screen.wait("Install qshd");
    client.master.write_all(b"yes\n").unwrap();
    screen.wait("Uploading qshd");
    std::thread::sleep(Duration::from_millis(200));
    client.master.write_all(b"\x03").unwrap();
    assert_eq!(wait_for_exit(&mut client.child).unwrap().code(), Some(130));
    assert_eq!(nix::sys::termios::tcgetattr(&slave).unwrap(), original);
    assert!(!image_path(&sb).exists());
}
#[test]
fn background_never_installs_even_with_cached_image() {
    let _serial = serialised();
    let home = tempfile::tempdir().unwrap();
    let (daemon, identity) = start_daemon();
    let key = ssh_key::PrivateKey::read_openssh_file(&identity).unwrap();
    let sb = Sandbox::start_with(&[key.public_key().to_openssh().unwrap()]);
    trust(home.path(), &sb);
    seed(home.path());
    let relay = UdpRelay::start(daemon.port);
    let address = format!("127.0.0.1:{},ssh={}", relay.port, sb.sshd.port);
    let mut client = spawn_qsh(
        &[
            "--authorize-ssh",
            "--verbose",
            "-i",
            identity.to_str().unwrap(),
            &address,
        ],
        home.path(),
    );
    let screen = Screen::of(&client);
    screen.wait("Key fingerprint");
    client.master.write_all(b"yes\n").unwrap();
    screen.wait("Authorize SSH recovery");
    client.master.write_all(b"yes\n").unwrap();
    client.type_line("echo BEFORE_'RECOVERY'");
    screen.wait("BEFORE_RECOVERY");
    relay.cut();
    client.master.write_all(b"\x1dr").unwrap();
    assert!(
        wait_until(|| std::fs::read_to_string(home.path().join("qsh/log"))
            .unwrap_or_default()
            .contains("qshd is missing; recovery will not install it")),
        "{}",
        screen.text()
    );
    assert!(!image_path(&sb).exists());
    assert!(!screen.text().contains("Install qshd"));
    relay.restore();
    for _ in 0..15 {
        client.type_line("echo UDP_'RECOVERED'");
        if wait_for_marker(&screen, "UDP_RECOVERED", Duration::from_secs(1)) {
            break;
        }
    }
    screen.wait("UDP_RECOVERED");
    client.type_line("exit");
    assert!(wait_for_exit(&mut client.child).unwrap().success());
}
fn wait_for_marker(screen: &Screen, needle: &str, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if screen.text().contains(needle) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

#[test]
fn ctrl_c_at_server_trust_still_cancels_login() {
    let _serial = serialised();
    let home = tempfile::tempdir().unwrap();
    let (daemon, identity) = start_daemon();
    let address = format!("127.0.0.1:{}", daemon.port);
    let (mut client, screen) = start(home.path(), &identity, &[address]);
    screen.wait("Key fingerprint");
    client.master.write_all(b"\x03").unwrap();
    assert_eq!(wait_for_exit(&mut client.child).unwrap().code(), Some(130));
}

fn exits_promptly(client: &mut Client, screen: &Screen) -> std::process::ExitStatus {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(status) = client.child.try_wait().unwrap() {
            return status;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "cancellation did not exit within two seconds: {}",
            screen.text()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn ctrl_c_at_visible_keyboard_interactive_challenge() {
    use base64::Engine as _;
    use support_home::ssh_support::fake_server::{FakeAuth, FakeServer};
    let _serial = serialised();
    let home = tempfile::tempdir().unwrap();
    let (identity, _) = key(home.path());
    let server = FakeServer::start(FakeAuth {
        kbd_rounds: vec![vec![("Visible challenge: ".into(), true, "42".into())]],
        ..FakeAuth::default()
    });
    let ssh_dir = home.path().join(".ssh");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    std::fs::write(
        ssh_dir.join("known_hosts"),
        format!(
            "[127.0.0.1]:{} ssh-ed25519 {}\n",
            server.port,
            base64::engine::general_purpose::STANDARD.encode(server.host_public_key_wire())
        ),
    )
    .unwrap();
    let address = format!("127.0.0.1:{},ssh={}", free_udp_port(), server.port);
    let (mut client, screen) = start(home.path(), &identity, &[address]);
    screen.wait("Visible challenge: ");
    client.master.write_all(b"\x03").unwrap();
    assert_eq!(exits_promptly(&mut client, &screen).code(), Some(130));
}

#[test]
fn ctrl_c_during_first_udp_address_skips_remaining_addresses() {
    let _serial = serialised();
    let home = tempfile::tempdir().unwrap();
    let (identity, _) = key(home.path());
    let first = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let second = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    first
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    second
        .set_read_timeout(Some(Duration::from_millis(150)))
        .unwrap();
    let addresses = [
        first.local_addr().unwrap().to_string(),
        second.local_addr().unwrap().to_string(),
    ];
    let (mut client, screen) = start(home.path(), &identity, &addresses);
    let mut datagram = [0; 512];
    first
        .recv_from(&mut datagram)
        .expect("the first address must be in discovery before cancellation");
    client.master.write_all(b"\x03").unwrap();
    assert_eq!(exits_promptly(&mut client, &screen).code(), Some(130));
    assert!(
        second.recv_from(&mut datagram).is_err(),
        "cancellation must never visit the second address"
    );
    let log = std::fs::read_to_string(home.path().join("qsh/log")).unwrap();
    assert!(!log.contains("ladder: address 1:"), "{log}");
}
