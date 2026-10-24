//! Controlled user startup files; system shell configuration is qualified separately.
#![cfg(unix)]
mod support;

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use support::*;

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

// Per-child contamination avoids changing the concurrently running test process.
fn isolated(test: &str, shell: &Path, foreign_startup: bool) -> bool {
    if std::env::var_os("QSH_SHELL_FIXTURE_CHILD").is_some() {
        return true;
    }
    let foreign = tempfile::Builder::new()
        .prefix("foreign shell ' ")
        .tempdir()
        .unwrap();
    let marker = foreign.path().join("startup-ran");
    let body = format!(
        "printf 'FOREIGN_STARTUP\\n'; printf x > {}\n",
        shell_env::quote(&marker)
    );
    if foreign_startup {
        for file in [".zshenv", ".zshrc", "bash-env", "env"] {
            std::fs::write(foreign.path().join(file), &body).unwrap();
        }
    }
    let mut log = tempfile::tempfile().unwrap();
    let mut child = OwnedChild(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture"])
            .env("QSH_SHELL_FIXTURE_CHILD", "1")
            .env("HOME", foreign.path())
            .env("XDG_CACHE_HOME", foreign.path())
            .env("XDG_CONFIG_HOME", foreign.path())
            .env("SHELL", shell)
            .env("ZDOTDIR", foreign.path())
            .env("BASH_ENV", foreign.path().join("bash-env"))
            .env("ENV", foreign.path().join("env"))
            .env("HISTFILE", "/dev/null")
            .env_remove("SSH_AUTH_SOCK")
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log.try_clone().unwrap())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(90);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "private-shell child timed out");
        std::thread::sleep(Duration::from_millis(20));
    };
    log.seek(SeekFrom::Start(0)).unwrap();
    let mut output = String::new();
    log.read_to_string(&mut output).unwrap();
    assert!(status.success(), "private-shell child failed: {output}");
    assert!(
        output.contains("1 passed; 0 failed"),
        "selected test did not run: {output}"
    );
    assert!(!marker.exists(), "foreign startup file was sourced");
    false
}

fn installed_shell(name: &str) -> Option<PathBuf> {
    let found = ["/bin", "/usr/bin"]
        .into_iter()
        .map(|dir| Path::new(dir).join(name))
        .find(|path| path.is_file());
    if found.is_none() {
        assert!(
            std::env::var_os("QSH_REQUIRE_TEST_SHELLS").is_none(),
            "required test shell missing: {name}"
        );
        eprintln!("SKIPPED: explicit {name} shell coverage requires installed {name}");
    }
    found
}

#[test]
fn generic_fixture_executes_first_command_in_predictable_shell() {
    let name = "generic_fixture_executes_first_command_in_predictable_shell";
    if !isolated(name, Path::new("/bin/bash"), true) {
        return;
    }
    let _serial = serialised();
    let (daemon, key) = start_daemon();
    check_shell(&daemon, &key, "sh");
}

#[test]
fn explicit_bash_ignores_foreign_startup_and_survives_restart() {
    explicit(
        "explicit_bash_ignores_foreign_startup_and_survives_restart",
        "bash",
        true,
    );
}

#[test]
fn explicit_zsh_executes_first_input_without_newuser_wizard() {
    explicit(
        "explicit_zsh_executes_first_input_without_newuser_wizard",
        "zsh",
        false,
    );
}

#[test]
fn explicit_zsh_ignores_foreign_startup_and_survives_restart() {
    explicit(
        "explicit_zsh_ignores_foreign_startup_and_survives_restart",
        "zsh",
        true,
    );
}

fn explicit(test: &str, shell: &str, foreign: bool) {
    let Some(path) = installed_shell(shell) else {
        return;
    };
    if !isolated(test, &path, foreign) {
        return;
    }
    let _serial = serialised();
    let (mut daemon, key) = start_daemon_with_shell(&path);
    check_shell(&daemon, &key, shell);
    daemon.restart();
    check_shell(&daemon, &key, shell);
}

#[test]
fn tracked_shell_takes_precedence_after_restart() {
    let name = "tracked_shell_takes_precedence_after_restart";
    if !isolated(name, Path::new("/bin/bash"), true) {
        return;
    }
    let _serial = serialised();
    let (mut daemon, key) = start_daemon_with_shell(Path::new("/bin/bash"));
    daemon.track_shell_starts();
    daemon.restart();
    check_shell(&daemon, &key, "sh");
    assert_eq!(daemon.shell_starts(), 1);
}

struct ObservedClient {
    client: Option<Client>,
    reader: Option<std::thread::JoinHandle<()>>,
}
impl Drop for ObservedClient {
    fn drop(&mut self) {
        drop(self.client.take());
        self.reader.take().unwrap().join().unwrap();
    }
}

fn check_shell(daemon: &Daemon, key: &Path, identity: &str) {
    let config = tempfile::tempdir().unwrap();
    let client = spawn_client(daemon, key, config.path());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let output = seen.clone();
    let mut reader = client.master.try_clone().unwrap();
    let collector = std::thread::spawn(move || {
        let mut bytes = [0; 4096];
        while let Ok(n) = reader.read(&mut bytes) {
            if n == 0 {
                break;
            }
            output.lock().unwrap().extend_from_slice(&bytes[..n]);
        }
    });
    let mut observed = ObservedClient {
        client: Some(client),
        reader: Some(collector),
    };
    let client = observed.client.as_mut().unwrap();
    let text = || String::from_utf8_lossy(&seen.lock().unwrap()).into_owned();
    assert!(
        wait_until(|| text().contains("Key fingerprint")),
        "{}",
        text()
    );
    client.master.write_all(b"yes\n").unwrap();
    // Contiguous markers never occur in the typed command. The nested Bash
    // command also exercises BASH_ENV, which interactive Bash does not read.
    client.type_line("printf 'FIRST_%s\\n' INPUT; printf 'IDENTITY_%s\\n' \"${0##*/}\"; /bin/bash -c \"printf 'NESTED_%s\\\\n' CLEAN\"");
    assert!(
        wait_until(|| text().contains("FIRST_INPUT")),
        "first command lost: {}",
        text()
    );
    assert!(
        wait_until(|| text().contains(&format!("IDENTITY_{identity}"))),
        "wrong shell: {}",
        text()
    );
    assert!(
        wait_until(|| text().contains("NESTED_CLEAN")),
        "nested command lost: {}",
        text()
    );
    assert!(
        !text().contains("zsh-newuser-install"),
        "wizard ran: {}",
        text()
    );
    assert!(
        !text().contains("FOREIGN_STARTUP"),
        "foreign startup ran: {}",
        text()
    );
    client.type_line("exit");
    assert_eq!(wait_for_exit(&mut client.child).unwrap().code(), Some(0));
}
