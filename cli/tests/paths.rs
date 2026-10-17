//! Portable client-path tests without the Linux-only daemon test harness.
#[path = "../src/paths.rs"]
mod paths;
use qsh::{log, sessions};

mod tests {
    use super::paths::*;
    use sshauth::known_hosts::{HostVerdict, KnownHosts};
    use std::os::unix::fs::symlink;
    use std::{
        ffi::OsStr,
        path::{Path, PathBuf},
    };

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
            assert!(!std::fs::symlink_metadata(&config)
                .unwrap()
                .file_type()
                .is_symlink());
            let hosts = KnownHosts::open(config.join("known_hosts"));
            assert_eq!(
                hosts.check("example.org", 60000, &[7; 32]).unwrap(),
                HostVerdict::Unknown
            );
            let old = KnownHosts::open(home.join("Library/Application Support/qsh/known_hosts"));
            assert_eq!(
                old.check("example.org", 60000, &[7; 32]).unwrap(),
                HostVerdict::Known
            );
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
                    "tests::configured_paths_follow_environment_in_an_isolated_process",
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
    fn old_directory_is_not_imported() {
        let home = tempfile::tempdir().unwrap();
        let old = home.path().join("Library/Application Support/qsh");
        let new = home.path().join(".config/qsh");
        KnownHosts::open(old.join("known_hosts"))
            .pin("example.org", 60000, &[7; 32])
            .unwrap();
        prepare_at(&new).unwrap();
        assert!(!std::fs::symlink_metadata(&new)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(!new.join("known_hosts").exists());
    }

    #[test]
    fn existing_xdg_store_is_preserved() {
        let home = tempfile::tempdir().unwrap();
        let old = home.path().join("old");
        let new = home.path().join("new");
        std::fs::create_dir(&old).unwrap();
        std::fs::create_dir(&new).unwrap();
        std::fs::write(old.join("known_hosts"), "old data").unwrap();
        std::fs::write(new.join("known_hosts"), "new data").unwrap();
        prepare_at(&new).unwrap();
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
    fn fresh_setup_creates_a_private_directory() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let new = home.path().join("config/qsh");
        prepare_at(&new).unwrap();
        assert_eq!(
            std::fs::metadata(&new).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert!(!new.join("known_hosts").exists());
    }

    #[test]
    fn unusable_xdg_directory_is_reported() {
        let home = tempfile::tempdir().unwrap();
        let config = home.path().join("config");
        symlink(home.path().join("missing"), &config).unwrap();
        assert!(prepare_at(&config).is_err());
        std::fs::remove_file(&config).unwrap();
        std::fs::write(&config, "not a directory").unwrap();
        assert!(prepare_at(&config).is_err());
    }
}
