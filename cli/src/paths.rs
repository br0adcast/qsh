//! Console-client state locations and compatibility with existing macOS stores.

use std::{
    ffi::OsStr,
    io,
    path::{Path, PathBuf},
};

/// Unix clients use XDG; other targets retain their native directory defaults.
pub fn config_dir() -> PathBuf {
    #[cfg(unix)]
    {
        unix_root(
            &home(),
            std::env::var_os("XDG_CONFIG_HOME").as_deref(),
            ".config",
        )
    }
    #[cfg(not(unix))]
    {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("qsh")
    }
}

pub fn cache_dir() -> PathBuf {
    #[cfg(unix)]
    {
        unix_root(
            &home(),
            std::env::var_os("XDG_CACHE_HOME").as_deref(),
            ".cache",
        )
    }
    #[cfg(not(unix))]
    {
        dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("qsh")
    }
}

#[cfg(unix)]
fn home() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("."))
}

pub(crate) fn unix_root(home: &Path, configured: Option<&OsStr>, default: &str) -> PathBuf {
    configured
        .map(Path::new)
        .filter(|path| path.is_absolute())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| home.join(default))
        .join("qsh")
}

/// Prepare the store before reading pins or claiming a session. On macOS,
/// an atomic directory alias keeps the old data and its lock inodes shared
/// with clients that are already running. Copying sessions would lose locks;
/// linking only known_hosts would break on its next atomic rename.
pub fn prepare_config() -> io::Result<PathBuf> {
    let config = config_dir();
    #[cfg(target_os = "macos")]
    let legacy = Some(home().join("Library/Application Support/qsh"));
    #[cfg(not(target_os = "macos"))]
    let legacy: Option<PathBuf> = None;
    prepare_at(&config, legacy.as_deref())?;
    Ok(config)
}

fn private_directory(path: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "cannot prepare configuration directory \"{}\": {error}",
                path.display()
            ),
        )
    })
}

fn prepare_at(config: &Path, legacy: Option<&Path>) -> io::Result<()> {
    #[cfg(unix)]
    if let Some(legacy) = legacy {
        match std::fs::symlink_metadata(legacy) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!(
                        "cannot inspect previous configuration \"{}\": {error}",
                        legacy.display()
                    ),
                ))
            }
            Ok(_) => return link_existing(config, legacy),
        }
    }
    #[cfg(not(unix))]
    let _ = legacy;
    private_directory(config)
}

#[cfg(unix)]
fn link_existing(config: &Path, legacy: &Path) -> io::Result<()> {
    let conflict = || {
        io::Error::new(io::ErrorKind::AlreadyExists, format!(
        "cannot migrate configuration from \"{}\" to \"{}\": both paths must refer to the same directory; \
         close old clients and reconcile these paths manually before reconnecting (no data was overwritten)",
        legacy.display(), config.display()))
    };
    let old = std::fs::canonicalize(legacy).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "cannot open previous configuration \"{}\": {error}",
                legacy.display()
            ),
        )
    })?;
    if !old.is_dir() {
        return Err(conflict());
    }
    match std::fs::symlink_metadata(config) {
        Ok(_) => {
            return if std::fs::canonicalize(config).map_err(|_| conflict())? == old {
                Ok(())
            } else {
                Err(conflict())
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let parent = config.parent().ok_or_else(conflict)?;
    private_directory(parent)?;
    if std::fs::canonicalize(parent)?.starts_with(&old) {
        return Err(conflict());
    }
    match std::os::unix::fs::symlink(&old, config) {
        Ok(()) => Ok(()),
        // A concurrent client may have installed the same alias first.
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            if std::fs::canonicalize(config).map_err(|_| conflict())? == old {
                Ok(())
            } else {
                Err(conflict())
            }
        }
        Err(error) => Err(io::Error::new(
            error.kind(),
            format!(
                "cannot link configuration \"{}\" to \"{}\": {error}",
                config.display(),
                old.display()
            ),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sessions;
    use sshauth::known_hosts::{HostVerdict, KnownHosts};
    use std::os::unix::fs::symlink;

    #[test]
    fn configured_paths_follow_environment_in_an_isolated_process() {
        if let Ok(mode) = std::env::var("QSH_TEST_PATHS_CHILD") {
            let home = dirs::home_dir().unwrap();
            let config = home.join(if mode == "xdg" {
                "custom config/qsh"
            } else {
                ".config/qsh"
            });
            let cache = home.join(if mode == "xdg" {
                "custom cache/qsh"
            } else {
                ".cache/qsh"
            });
            assert_eq!(prepare_config().unwrap(), config);
            assert_eq!(cache_dir(), cache);
            assert_eq!(crate::sessions::default_dir(), config.join("sessions"));
            assert_eq!(crate::log::path(), cache.join("log"));
            if cfg!(target_os = "macos") {
                let hosts = KnownHosts::open(config.join("known_hosts"));
                assert_eq!(
                    hosts.check("example.org", 60000, &[7; 32]).unwrap(),
                    HostVerdict::Known
                );
            }
            return;
        }
        for mode in ["default", "xdg"] {
            let home = tempfile::tempdir().unwrap();
            let old = home
                .path()
                .join("Library/Application Support/qsh/known_hosts");
            KnownHosts::open(old)
                .pin("example.org", 60000, &[7; 32])
                .unwrap();
            let mut child = std::process::Command::new(std::env::current_exe().unwrap());
            child
                .args([
                    "--exact",
                    "paths::tests::configured_paths_follow_environment_in_an_isolated_process",
                    "--nocapture",
                ])
                .env("QSH_TEST_PATHS_CHILD", mode)
                .env("HOME", home.path())
                .env("HISTFILE", "/dev/null")
                .env_remove("XDG_CONFIG_HOME")
                .env_remove("XDG_CACHE_HOME");
            if mode == "xdg" {
                child
                    .env("XDG_CONFIG_HOME", home.path().join("custom config"))
                    .env("XDG_CACHE_HOME", home.path().join("custom cache"));
            }
            assert!(child.status().unwrap().success(), "{mode}");
        }
    }

    #[test]
    fn unix_paths_use_xdg_or_dot_directories() {
        let home = Path::new("/example/home");
        assert_eq!(unix_root(home, None, ".config"), home.join(".config/qsh"));
        assert_eq!(unix_root(home, None, ".cache"), home.join(".cache/qsh"));
        assert_eq!(
            unix_root(home, Some(OsStr::new("/example/custom path")), ".config"),
            PathBuf::from("/example/custom path/qsh")
        );
        for invalid in ["", "relative/path"] {
            assert_eq!(
                unix_root(home, Some(OsStr::new(invalid)), ".config"),
                home.join(".config/qsh")
            );
        }
    }

    #[test]
    fn migration_preserves_trust_updates_and_live_session_locks() {
        let home = tempfile::tempdir().unwrap();
        let old = home.path().join("Library/Application Support/qsh");
        let new = home.path().join(".config/qsh");
        let old_hosts = KnownHosts::open(old.join("known_hosts"));
        old_hosts.pin("example.org", 60000, &[7; 32]).unwrap();
        let live = sessions::claim(&old.join("sessions"), "example.org", 60000);
        prepare_at(&new, Some(&old)).unwrap();
        let new_hosts = KnownHosts::open(new.join("known_hosts"));
        assert_eq!(
            new_hosts.check("example.org", 60000, &[7; 32]).unwrap(),
            HostVerdict::Known
        );
        let other = sessions::claim(&new.join("sessions"), "example.org", 60000);
        assert_ne!(
            other.token, live.token,
            "the old client's lock still protects its shell"
        );
        new_hosts.pin("another.example", 60000, &[8; 32]).unwrap();
        assert_eq!(
            old_hosts.check("another.example", 60000, &[8; 32]).unwrap(),
            HostVerdict::Known
        );
        let token = live.token;
        drop(live);
        assert_eq!(
            sessions::claim(&new.join("sessions"), "example.org", 60000).token,
            token
        );
        assert!(old.is_dir(), "original data remains in place");
        prepare_at(&new, Some(&old)).unwrap();
    }

    #[test]
    fn conflicting_directories_are_not_merged_or_overwritten() {
        let home = tempfile::tempdir().unwrap();
        let old = home.path().join("old");
        let new = home.path().join("new");
        std::fs::create_dir(&old).unwrap();
        std::fs::create_dir(&new).unwrap();
        std::fs::write(old.join("known_hosts"), "old data").unwrap();
        std::fs::write(new.join("known_hosts"), "new data").unwrap();
        let error = prepare_at(&new, Some(&old)).unwrap_err().to_string();
        assert!(error.contains(&old.display().to_string()), "{error}");
        assert!(error.contains(&new.display().to_string()), "{error}");
        assert_eq!(
            std::fs::read_to_string(old.join("known_hosts")).unwrap(),
            "old data"
        );
        assert_eq!(
            std::fs::read_to_string(new.join("known_hosts")).unwrap(),
            "new data"
        );
    }

    #[test]
    fn concurrent_migration_is_atomic_and_idempotent() {
        let home = tempfile::tempdir().unwrap();
        let old = home.path().join("old");
        let new = home.path().join("config/qsh");
        std::fs::create_dir(&old).unwrap();
        std::thread::scope(|scope| {
            let first = scope.spawn(|| prepare_at(&new, Some(&old)));
            let second = scope.spawn(|| prepare_at(&new, Some(&old)));
            first.join().unwrap().unwrap();
            second.join().unwrap().unwrap();
        });
        assert_eq!(
            std::fs::canonicalize(&new).unwrap(),
            std::fs::canonicalize(&old).unwrap()
        );
    }

    #[test]
    fn fresh_setup_creates_a_private_directory_without_legacy_state() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let new = home.path().join("config/qsh");
        prepare_at(&new, Some(&home.path().join("absent"))).unwrap();
        assert_eq!(
            std::fs::metadata(&new).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert!(!new.join("known_hosts").exists());
    }

    #[test]
    fn broken_links_and_non_directories_do_not_silently_reset_trust() {
        let home = tempfile::tempdir().unwrap();
        let old = home.path().join("old");
        let new = home.path().join("new");
        symlink(home.path().join("missing"), &old).unwrap();
        assert!(prepare_at(&new, Some(&old)).is_err());
        assert!(!new.exists());
        std::fs::remove_file(&old).unwrap();
        symlink(home.path().join("missing"), &new).unwrap();
        assert!(prepare_at(&new, Some(&old)).is_err());
        std::fs::remove_file(&new).unwrap();
        std::fs::write(&old, "not a directory").unwrap();
        assert!(prepare_at(&new, Some(&old)).is_err());
    }

    #[test]
    fn existing_aliases_are_accepted_but_nested_destinations_are_refused() {
        let home = tempfile::tempdir().unwrap();
        let old = home.path().join("old");
        let alias = home.path().join("alias");
        std::fs::create_dir(&old).unwrap();
        symlink(&old, &alias).unwrap();
        prepare_at(&alias, Some(&old)).unwrap();
        prepare_at(&old, Some(&old)).unwrap();
        assert!(prepare_at(&old.join("nested/qsh"), Some(&old)).is_err());
    }
}
