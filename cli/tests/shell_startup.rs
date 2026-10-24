//! Controlled user startup files; system shell configuration is qualified separately.
#![cfg(unix)]
mod support;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use support::*;

// The synthetic startup state and the daemon/client guards stay owned by this
// test process, including while an assertion unwinds.
struct ForeignStartup {
    home: tempfile::TempDir,
    env: Vec<(String, String)>,
}

impl ForeignStartup {
    fn new(shell: &Path, foreign_startup: bool) -> Self {
        let home = tempfile::Builder::new()
            .prefix("foreign shell ' ")
            .tempdir()
            .unwrap();
        let marker = home.path().join("startup-ran");
        let body = format!(
            "printf 'FOREIGN_STARTUP\\n'; printf x > {}\n",
            shell_env::quote(&marker)
        );
        if foreign_startup {
            for file in [".zshenv", ".zshrc", "bash-env", "env"] {
                std::fs::write(home.path().join(file), &body).unwrap();
            }
        }
        let h = home.path().to_str().unwrap().to_owned();
        let env = vec![
            ("HOME".into(), h.clone()),
            ("XDG_CACHE_HOME".into(), h.clone()),
            ("XDG_CONFIG_HOME".into(), h.clone()),
            ("SHELL".into(), shell.to_str().unwrap().into()),
            ("ZDOTDIR".into(), h.clone()),
            ("BASH_ENV".into(), format!("{h}/bash-env")),
            ("ENV".into(), format!("{h}/env")),
            ("HISTFILE".into(), "/dev/null".into()),
            ("QSH_FIXTURE_CANARY".into(), "owned-startup".into()),
        ];
        Self { home, env }
    }

    fn assert_not_sourced(&self) {
        assert!(
            !self.home.path().join("startup-ran").exists(),
            "foreign startup file was sourced"
        );
    }
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
    let _serial = serialised();
    let foreign = ForeignStartup::new(Path::new("/bin/bash"), true);
    let (daemon, key) = start_daemon_with_shell_env(Path::new("/bin/sh"), &foreign.env);
    check_shell(&daemon, &key, "sh");
    foreign.assert_not_sourced();
}

#[test]
fn explicit_bash_ignores_foreign_startup_and_survives_restart() {
    explicit("bash", true);
}

#[test]
fn explicit_zsh_executes_first_input_without_newuser_wizard() {
    explicit("zsh", false);
}

#[test]
fn explicit_zsh_ignores_foreign_startup_and_survives_restart() {
    explicit("zsh", true);
}

fn explicit(shell: &str, foreign_startup: bool) {
    let Some(path) = installed_shell(shell) else {
        return;
    };
    let _serial = serialised();
    let foreign = ForeignStartup::new(&path, foreign_startup);
    let (mut daemon, key) = start_daemon_with_shell_env(&path, &foreign.env);
    check_shell(&daemon, &key, shell);
    foreign.assert_not_sourced();
    daemon.restart();
    check_shell(&daemon, &key, shell);
    foreign.assert_not_sourced();
}

#[test]
fn tracked_shell_takes_precedence_after_restart() {
    let _serial = serialised();
    let foreign = ForeignStartup::new(Path::new("/bin/bash"), true);
    let (mut daemon, key) = start_daemon_with_shell_env(Path::new("/bin/bash"), &foreign.env);
    daemon.track_shell_starts();
    daemon.restart();
    check_shell(&daemon, &key, "sh");
    assert_eq!(daemon.shell_starts(), 1);
    foreign.assert_not_sourced();
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
    check_shell_ready(daemon, key, identity, |_| {});
}

fn check_shell_ready(daemon: &Daemon, key: &Path, identity: &str, ready: impl FnOnce(u32)) {
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
    client.type_line("printf 'FIRST_%s\\n' INPUT; printf 'IDENTITY_%s\\n' \"${0##*/}\"; /bin/bash -c \"printf 'NESTED_%s\\\\n' CLEAN\"; printf 'CANARY_%s\\n' \"$QSH_FIXTURE_CANARY\"");
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
        wait_until(|| text().contains("CANARY_owned-startup")),
        "injected environment missing: {}",
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
    ready(client.child.id());
    client.type_line("exit");
    assert_eq!(wait_for_exit(&mut client.child).unwrap().code(), Some(0));
}

#[test]
fn assertion_unwind_reaps_live_daemon_and_client() {
    use std::cell::Cell;
    let _serial = serialised();
    let foreign = ForeignStartup::new(Path::new("/bin/bash"), true);
    let daemon_pid = Cell::new(0);
    let client_pid = Cell::new(0);
    let reached = Cell::new(false);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let (daemon, key) = start_daemon_with_shell_env(Path::new("/bin/sh"), &foreign.env);
        daemon_pid.set(daemon.child.id());
        check_shell_ready(&daemon, &key, "sh", |pid| {
            client_pid.set(pid);
            assert_owned_live(daemon_pid.get());
            assert_owned_live(pid);
            reached.set(true);
            panic!("intentional assertion unwind with live fixture children");
        });
    }));
    assert!(
        result.is_err() && reached.get(),
        "control must reach the live-shell assertion"
    );
    assert_reaped(daemon_pid.get());
    assert_reaped(client_pid.get());
    eprintln!(
        "unwind control reaped owned daemon PID {} and client PID {}",
        daemon_pid.get(),
        client_pid.get()
    );
    foreign.assert_not_sourced();
}

fn assert_owned_live(pid: u32) {
    let mut status = 0;
    // These are direct children created by this test, still protected by their
    // guards. WNOHANG observes ownership without signalling or blocking.
    assert_eq!(
        unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) },
        0
    );
}

fn assert_reaped(pid: u32) {
    assert_ne!(pid, 0);
    let mut status = 0;
    // A child that was merely killed but not waited would return its PID here.
    // ECHILD proves the owning guard already completed its wait.
    assert_eq!(
        unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}
