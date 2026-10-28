//! Console-client configuration, cache and SSH locations.
//!
//! One policy for every client path: an absolute `$XDG_CONFIG_HOME` or
//! `$XDG_CACHE_HOME` wins, otherwise the directory lives under the home
//! directory. An unknown home directory is never replaced by the current
//! directory: a path that needs it is an error, or, for the optional
//! `~/.ssh` defaults, absent.

use std::{
    ffi::OsStr,
    io,
    path::{Path, PathBuf},
};

/// `$XDG_CONFIG_HOME/qsh`, otherwise `~/.config/qsh`.
pub fn config_dir() -> io::Result<PathBuf> {
    root(
        std::env::var_os("XDG_CONFIG_HOME").as_deref(),
        home().as_deref(),
        ".config",
        "XDG_CONFIG_HOME",
    )
}

/// `$XDG_CACHE_HOME/qsh`, otherwise `~/.cache/qsh`.
pub fn cache_dir() -> io::Result<PathBuf> {
    root(
        std::env::var_os("XDG_CACHE_HOME").as_deref(),
        home().as_deref(),
        ".cache",
        "XDG_CACHE_HOME",
    )
}

/// `~/.ssh`, where the default keys and the user's `known_hosts` are; none
/// without a home directory.
pub fn ssh_dir() -> Option<PathBuf> {
    home().map(|home| home.join(".ssh"))
}

/// The account's home directory: `$HOME`, or the account database when it
/// is unset or empty.
fn home() -> Option<PathBuf> {
    dirs::home_dir()
}

/// The selected directory: `configured` when absolute (the XDG rule for
/// relative values is to ignore them), otherwise `default` under `home`.
fn root(
    configured: Option<&OsStr>,
    home: Option<&Path>,
    default: &str,
    variable: &str,
) -> io::Result<PathBuf> {
    configured
        .map(Path::new)
        .filter(|path| path.is_absolute())
        .map(Path::to_path_buf)
        .or_else(|| home.map(|home| home.join(default)))
        .map(|root| root.join("qsh"))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("no home directory is known; set HOME, or {variable} to an absolute path"),
            )
        })
}

/// Create the selected configuration directory before opening client state.
pub fn prepare_config() -> io::Result<PathBuf> {
    let config = config_dir().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("cannot locate the configuration directory: {error}"),
        )
    })?;
    prepare_at(&config)?;
    Ok(config)
}

fn prepare_at(path: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absolute_override_wins_and_needs_no_home() {
        let custom = Some(OsStr::new("/example/custom path"));
        for home in [Some(Path::new("/example/home")), None] {
            assert_eq!(
                root(custom, home, ".config", "XDG_CONFIG_HOME").unwrap(),
                PathBuf::from("/example/custom path/qsh")
            );
        }
    }

    #[test]
    fn without_an_absolute_override_the_home_default_is_used() {
        let home = Path::new("/example/home");
        for configured in [None, Some(""), Some("relative/path")] {
            let configured = configured.map(OsStr::new);
            assert_eq!(
                root(configured, Some(home), ".config", "XDG_CONFIG_HOME").unwrap(),
                home.join(".config/qsh")
            );
            assert_eq!(
                root(configured, Some(home), ".cache", "XDG_CACHE_HOME").unwrap(),
                home.join(".cache/qsh")
            );
        }
    }

    #[test]
    fn without_a_home_only_an_absolute_override_is_accepted() {
        for configured in [None, Some(""), Some("relative/path")] {
            let error =
                root(configured.map(OsStr::new), None, ".cache", "XDG_CACHE_HOME").unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::NotFound);
            assert_eq!(
                error.to_string(),
                "no home directory is known; set HOME, or XDG_CACHE_HOME to an absolute path"
            );
        }
    }
}
