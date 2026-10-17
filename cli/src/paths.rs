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

pub(crate) fn prepare_at(config: &Path, legacy: Option<&Path>) -> io::Result<()> {
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
