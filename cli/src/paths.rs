//! Console-client configuration and cache locations.

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

/// Create the selected configuration directory before opening client state.
pub fn prepare_config() -> io::Result<PathBuf> {
    let config = config_dir();
    prepare_at(&config)?;
    Ok(config)
}

pub(crate) fn prepare_at(path: &Path) -> io::Result<()> {
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
