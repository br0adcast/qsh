//! Portable client-path tests without the Linux-only daemon test harness.
//!
//! Each test runs its body again in a child process with `HOME` and the XDG
//! variables set for it, and observes the client's own path functions
//! there: the home defaults, absolute XDG overrides, ignored relative ones,
//! and how the configuration directory is created. The unknown-home case,
//! which no environment produces for an account the database knows, is
//! covered by the unit tests beside each caller.

use qsh::{log, paths};
use sshauth::known_hosts::{HostVerdict, KnownHosts};
use std::{
    ffi::OsStr,
    os::unix::fs::{symlink, PermissionsExt},
    path::{Path, PathBuf},
};

const CHILD: &str = "QSH_TEST_PATHS_CHILD";

/// The scenario this process runs, when it is a child [`run_child`] started.
fn child_scenario() -> Option<String> {
    std::env::var(CHILD).ok()
}

/// Runs `test` alone in a child whose working directory is `home` and whose
/// environment has `HOME`, `XDG_CONFIG_HOME` and `XDG_CACHE_HOME` as given
/// (`None` removes one), with `scenario` in [`CHILD`], and checks that it
/// passed.
fn run_child(
    test: &str,
    scenario: &str,
    home: &Path,
    config: Option<&OsStr>,
    cache: Option<&OsStr>,
) {
    let mut child = std::process::Command::new(std::env::current_exe().unwrap());
    child
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .current_dir(home)
        .env(CHILD, scenario)
        .env("HOME", home)
        .env("HISTFILE", "/dev/null");
    for (name, value) in [("XDG_CONFIG_HOME", config), ("XDG_CACHE_HOME", cache)] {
        match value {
            Some(value) => child.env(name, value),
            None => child.env_remove(name),
        };
    }
    let output = child.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{test} ({scenario}): {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("1 passed"), "{test} ({scenario}): {stdout}");
}

fn env_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).unwrap())
}

fn assert_private_directory(path: &Path) {
    let metadata = std::fs::symlink_metadata(path).unwrap();
    assert!(metadata.is_dir(), "{}", path.display());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
}

#[test]
fn without_overrides_every_path_is_under_the_home_directory() {
    if child_scenario().is_none() {
        let home = tempfile::tempdir().unwrap();
        // A store the earlier macOS location held stays where it is.
        KnownHosts::open(
            home.path()
                .join("Library/Application Support/qsh/known_hosts"),
        )
        .pin("example.org", 60000, &[7; 32])
        .unwrap();
        run_child(
            "without_overrides_every_path_is_under_the_home_directory",
            "home",
            home.path(),
            None,
            None,
        );
        return;
    }
    let home = env_path("HOME");
    let config = home.join(".config/qsh");
    let cache = home.join(".cache/qsh");
    assert_eq!(paths::config_dir().unwrap(), config);
    assert_eq!(paths::prepare_config().unwrap(), config);
    assert_private_directory(&config);
    assert_eq!(paths::cache_dir().unwrap(), cache);
    assert_eq!(log::path().unwrap(), cache.join("log"));
    assert_eq!(paths::ssh_dir(), Some(home.join(".ssh")));
    assert!(!config.join("known_hosts").exists());
    assert_eq!(
        KnownHosts::open(config.join("known_hosts"))
            .check("example.org", 60000, &[7; 32])
            .unwrap(),
        HostVerdict::Unknown
    );
    assert_eq!(
        KnownHosts::open(home.join("Library/Application Support/qsh/known_hosts"))
            .check("example.org", 60000, &[7; 32])
            .unwrap(),
        HostVerdict::Known
    );
}

#[test]
fn absolute_xdg_overrides_select_the_configuration_and_cache_directories() {
    if child_scenario().is_none() {
        let home = tempfile::tempdir().unwrap();
        let config = home.path().join("custom config");
        let cache = home.path().join("custom cache");
        run_child(
            "absolute_xdg_overrides_select_the_configuration_and_cache_directories",
            "xdg",
            home.path(),
            Some(config.as_os_str()),
            Some(cache.as_os_str()),
        );
        assert!(!home.path().join(".config").exists());
        assert!(!home.path().join(".cache").exists());
        return;
    }
    let config = env_path("XDG_CONFIG_HOME").join("qsh");
    let cache = env_path("XDG_CACHE_HOME").join("qsh");
    assert_eq!(paths::prepare_config().unwrap(), config);
    assert_private_directory(&config);
    assert_eq!(paths::cache_dir().unwrap(), cache);
    assert_eq!(log::path().unwrap(), cache.join("log"));
    // The SSH files are OpenSSH's, under the home directory regardless.
    assert_eq!(paths::ssh_dir(), Some(env_path("HOME").join(".ssh")));
}

#[test]
fn relative_or_empty_xdg_values_are_ignored() {
    if child_scenario().is_none() {
        let home = tempfile::tempdir().unwrap();
        for (config, cache) in [("relative/config", ""), ("", "relative/cache")] {
            run_child(
                "relative_or_empty_xdg_values_are_ignored",
                "relative",
                home.path(),
                Some(OsStr::new(config)),
                Some(OsStr::new(cache)),
            );
        }
        assert!(!home.path().join("relative").exists());
        return;
    }
    let home = env_path("HOME");
    assert_eq!(paths::prepare_config().unwrap(), home.join(".config/qsh"));
    assert_eq!(paths::cache_dir().unwrap(), home.join(".cache/qsh"));
}

#[test]
fn an_existing_configuration_is_kept_and_an_unusable_one_is_reported() {
    if child_scenario().is_none() {
        let home = tempfile::tempdir().unwrap();
        let root = |name: &str| {
            let root = home.path().join(name);
            std::fs::create_dir(&root).unwrap();
            root
        };
        let kept = root("kept");
        std::fs::create_dir(kept.join("qsh")).unwrap();
        std::fs::write(kept.join("qsh/known_hosts"), "kept data").unwrap();
        let dangling = root("dangling");
        symlink(home.path().join("missing"), dangling.join("qsh")).unwrap();
        let file = root("file");
        std::fs::write(file.join("qsh"), "not a directory").unwrap();
        for (scenario, config) in [
            ("kept", &kept),
            ("unusable", &dangling),
            ("unusable", &file),
        ] {
            run_child(
                "an_existing_configuration_is_kept_and_an_unusable_one_is_reported",
                scenario,
                home.path(),
                Some(config.as_os_str()),
                None,
            );
        }
        assert!(!home.path().join("missing").exists());
        assert_eq!(
            std::fs::read_to_string(file.join("qsh")).unwrap(),
            "not a directory"
        );
        return;
    }
    let config = env_path("XDG_CONFIG_HOME").join("qsh");
    if child_scenario().as_deref() == Some("kept") {
        assert_eq!(paths::prepare_config().unwrap(), config);
        assert_eq!(
            std::fs::read_to_string(config.join("known_hosts")).unwrap(),
            "kept data"
        );
    } else {
        let error = paths::prepare_config().unwrap_err().to_string();
        assert!(
            error.starts_with(&format!(
                "cannot prepare configuration directory \"{}\"",
                config.display()
            )),
            "{error}"
        );
    }
}
