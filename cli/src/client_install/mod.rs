//! Explicit installation commands, separate from terminal session startup.
use std::{ffi::OsString, path::PathBuf};

pub mod store;

#[derive(Debug, PartialEq, Eq)]
pub struct Command {
    pub update: bool,
    pub version: Option<String>,
    pub prefix: Option<PathBuf>,
    pub help: bool,
}

pub fn parse(argv: &[OsString]) -> Result<Option<Command>, String> {
    if !argv
        .iter()
        .any(|a| a == "--self-install" || a == "--self-update")
    {
        return Ok(None);
    }
    let Some(first) = argv.first() else {
        return Ok(None);
    };
    if first != "--self-install" && first != "--self-update" {
        return Err("managed installation flags must come first".into());
    }
    let mut command = Command {
        update: first == "--self-update",
        version: None,
        prefix: None,
        help: false,
    };
    let mut rest = argv[1..].iter();
    while let Some(arg) = rest.next() {
        match arg.to_str() {
            Some("--help" | "-h") if !command.help => command.help = true,
            Some("--version") if command.version.is_none() => {
                let value = rest
                    .next()
                    .and_then(|a| a.to_str())
                    .ok_or("--version requires VERSION")?;
                command.version = Some(value.to_owned());
            }
            Some("--prefix") if !command.update && command.prefix.is_none() => {
                command.prefix = Some(PathBuf::from(rest.next().ok_or("--prefix requires PATH")?));
            }
            _ => return Err("invalid managed installation arguments".into()),
        }
    }
    Ok(Some(command))
}

#[derive(Clone, Copy)]
struct BuildIdentity<'a> {
    official: bool,
    version: &'a str,
    source: &'a str,
}

struct Quiet;
impl bringup::BringUpObserver for Quiet {
    fn on_progress(&self, _: bringup::BringUpProgress) {}
}

fn native_platform() -> Result<bringup::Platform, String> {
    let os = match std::env::consts::OS {
        "linux" => "Linux",
        "macos" => "Darwin",
        _ => return Err("managed installation supports Linux and macOS only".into()),
    };
    bringup::Platform::from_uname(os, std::env::consts::ARCH).map_err(|e| e.to_string())
}

fn package_copy(executable: &std::path::Path) -> bool {
    if ["/usr", "/opt", "/nix", "/snap", "/var/lib/flatpak"]
        .iter()
        .any(|p| executable.starts_with(p))
        || executable.components().any(|c| {
            matches!(
                c.as_os_str().to_str(),
                Some("Cellar" | ".linuxbrew" | ".nix-profile")
            )
        })
    {
        return true;
    }
    // Query installed package databases only. No shell, network, sudo or manager mutation.
    for (tool, query) in [("/usr/bin/dpkg-query", "--search"), ("/usr/bin/rpm", "-qf")] {
        if std::process::Command::new(tool)
            .arg(query)
            .arg(executable)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
        {
            return true;
        }
    }
    false
}

fn collisions(path: Option<&std::ffi::OsStr>, destination: &std::path::Path) -> Vec<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    path.into_iter()
        .flat_map(std::env::split_paths)
        .map(|p| p.join("qsh"))
        .filter(|p| {
            p != destination
                && std::fs::metadata(p)
                    .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
        .collect()
}

fn execute(
    command: &Command,
    identity: BuildIdentity<'_>,
    home: &std::path::Path,
    executable: &std::path::Path,
    path: Option<&std::ffi::OsStr>,
    images: &crate::releases::GitHubImages,
) -> Result<String, String> {
    if !identity.official {
        return Err("development/source builds cannot download, install or update the client; update the source and rebuild a compatible client".into());
    }
    let actual_executable = std::fs::canonicalize(executable)
        .map_err(|_| "could not resolve the actual running qsh executable")?;
    let executable = actual_executable.as_path();
    if package_copy(executable) {
        return Err("package-owned or system qsh must be changed through its package manager; use the official bootstrap for a separate home installation".into());
    }
    let platform = native_platform()?;
    if let Some(version) = &command.version {
        bringup::ImageRequest::new(platform, version).map_err(|e| e.to_string())?;
    }
    let previous = if command.update {
        Some(
            store::validate_running(
                home,
                executable,
                identity.version,
                platform.target(),
                identity.source,
            )
            .map_err(|e| e.to_string())?,
        )
    } else {
        None
    };
    let requested_prefix = previous
        .as_ref()
        .map(|p| p.prefix.clone())
        .or_else(|| command.prefix.clone())
        .unwrap_or_else(|| home.join(".local"));
    let prefix = store::preflight(home, &requested_prefix).map_err(|e| e.to_string())?;
    let destination = prefix.join("bin/qsh");
    let competing = if command.update {
        Vec::new()
    } else {
        collisions(path, &destination)
    };
    if !command.update {
        if std::fs::symlink_metadata(&destination).is_ok() {
            return Err(format!(
                "destination already exists and will not be overwritten: {}",
                destination.display()
            ));
        }
        if !competing.is_empty() && command.prefix.is_none() {
            return Err(format!("another qsh is on PATH at {}; use an explicit --prefix to acknowledge a separate installation", competing[0].display()));
        }
    }
    let timing = bringup::InstallTiming::default();
    let cancel = knock::Cancel::new();
    let selected = images
        .select_client_version(command.version.as_deref(), &timing, &cancel, &Quiet)
        .map_err(|e| e.to_string())?;
    if let Some(previous) = &previous {
        eprintln!(
            "qsh: current {}, selected {}, installation {}",
            previous.version,
            selected,
            destination.display()
        );
        match selected_order(&previous.version, &selected)? {
            std::cmp::Ordering::Less => {
                return Err(format!(
                    "refusing downgrade from {} to {}",
                    previous.version, selected
                ))
            }
            std::cmp::Ordering::Equal => {
                return Ok(format!(
                    "qsh {} is already installed at {}",
                    selected,
                    destination.display()
                ))
            }
            std::cmp::Ordering::Greater => (),
        }
    } else {
        eprintln!(
            "qsh: selected {}, installation {}",
            selected,
            destination.display()
        );
    }
    let request = bringup::ImageRequest::new(platform, &selected).map_err(|e| e.to_string())?;
    let image = images
        .load_client(&request, &timing, &cancel, &Quiet)
        .map_err(|e| e.to_string())?;
    let installed =
        store::publish(home, &prefix, &image, previous.as_ref()).map_err(|e| e.to_string())?;
    let mut message = format!(
        "Installed qsh {}. Run {}",
        selected,
        installed.executable.display()
    );
    if !competing.is_empty() {
        message.push_str(&format!(
            "\nExisting PATH copy: {}. PATH was not changed.",
            competing[0].display()
        ));
    }
    Ok(message)
}

fn selected_order(current: &str, selected: &str) -> Result<std::cmp::Ordering, String> {
    let parse = |s| semver::Version::parse(s).map_err(|_| "invalid release version".to_string());
    Ok(parse(selected)?.cmp(&parse(current)?))
}

/// Called before ordinary argument parsing, logging, settings or connection startup.
pub fn run(command: &Command) -> Result<String, String> {
    if command.help {
        return Ok(if command.update {
            "Usage: qsh --self-update [--version VERSION]"
        } else {
            "Usage: qsh --self-install [--version VERSION] [--prefix PATH]"
        }
        .into());
    }
    let identity = BuildIdentity {
        official: env!("QSH_CLIENT_OFFICIAL") == "1",
        version: env!("CARGO_PKG_VERSION"),
        source: env!("QSH_CLIENT_SOURCE"),
    };
    // Build refusal precedes even home/executable discovery, as well as network I/O.
    if !identity.official {
        return Err("development/source builds cannot download, install or update the client; update the source and rebuild a compatible client".into());
    }
    let home = dirs::home_dir().ok_or("could not determine your home directory")?;
    let executable = std::env::current_exe()
        .map_err(|_| "could not resolve the actual running qsh executable")?;
    execute(
        command,
        identity,
        &home,
        &executable,
        std::env::var_os("PATH").as_deref(),
        &crate::releases::GitHubImages::new(None),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn development_install_refuses_before_transport() {
        struct NeverFetch;
        impl crate::releases::ReleaseTransport for NeverFetch {
            fn fetch(
                &self,
                _: &str,
                _: crate::releases::FetchLimits,
                _: &knock::Cancel,
                _: &dyn bringup::BringUpObserver,
            ) -> Result<Vec<u8>, crate::releases::FetchError> {
                panic!("ineligible build contacted network")
            }
        }
        let images = crate::releases::GitHubImages::uncached(std::sync::Arc::new(NeverFetch));
        let command = Command {
            update: false,
            version: None,
            prefix: None,
            help: false,
        };
        let error = execute(
            &command,
            BuildIdentity {
                official: false,
                version: "0.7.0",
                source: "",
            },
            std::path::Path::new("/missing/home"),
            std::path::Path::new("/missing/qsh"),
            None,
            &images,
        )
        .unwrap_err();
        assert!(error.contains("development"));
    }
    #[test]
    fn package_install_and_unregistered_update_refuse_before_transport() {
        struct NeverFetch;
        impl crate::releases::ReleaseTransport for NeverFetch {
            fn fetch(
                &self,
                _: &str,
                _: crate::releases::FetchLimits,
                _: &knock::Cancel,
                _: &dyn bringup::BringUpObserver,
            ) -> Result<Vec<u8>, crate::releases::FetchError> {
                panic!("unregistered or package copy contacted network")
            }
        }
        let images = crate::releases::GitHubImages::uncached(std::sync::Arc::new(NeverFetch));
        let home = tempfile::tempdir().unwrap();
        let identity = BuildIdentity {
            official: true,
            version: "0.7.0",
            source: "fixture",
        };
        let mut command = Command {
            update: false,
            version: None,
            prefix: None,
            help: false,
        };
        assert!(execute(
            &command,
            identity,
            home.path(),
            std::path::Path::new("/usr/bin/qsh"),
            None,
            &images
        )
        .is_err());
        command.update = true;
        let manual = home.path().join("qsh");
        std::fs::write(&manual, b"manual fixture").unwrap();
        assert!(execute(&command, identity, home.path(), &manual, None, &images).is_err());
    }
    #[test]
    fn path_collision_refuses_default_but_explicit_prefix_reaches_verification() {
        struct Offline(std::sync::atomic::AtomicUsize);
        impl crate::releases::ReleaseTransport for Offline {
            fn fetch(
                &self,
                _: &str,
                _: crate::releases::FetchLimits,
                _: &knock::Cancel,
                _: &dyn bringup::BringUpObserver,
            ) -> Result<Vec<u8>, crate::releases::FetchError> {
                self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Err(crate::releases::FetchError::Rejected(
                    bringup::ImageError::Download("offline fixture".into()),
                ))
            }
        }
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let bin = home.path().join("other");
        std::fs::create_dir(&bin).unwrap();
        let foreign = bin.join("qsh");
        std::fs::write(&foreign, b"foreign fixture").unwrap();
        std::fs::set_permissions(&foreign, std::fs::Permissions::from_mode(0o700)).unwrap();
        let bootstrap = home.path().join("bootstrap");
        std::fs::write(&bootstrap, b"bootstrap fixture").unwrap();
        let transport = std::sync::Arc::new(Offline(std::sync::atomic::AtomicUsize::new(0)));
        let images = crate::releases::GitHubImages::uncached(transport.clone());
        let identity = BuildIdentity {
            official: true,
            version: "0.7.0",
            source: "fixture",
        };
        let mut command = Command {
            update: false,
            version: Some("0.7.0".into()),
            prefix: None,
            help: false,
        };
        let error = execute(
            &command,
            identity,
            home.path(),
            &bootstrap,
            Some(bin.as_os_str()),
            &images,
        )
        .unwrap_err();
        assert!(error.contains("PATH"));
        assert_eq!(transport.0.load(std::sync::atomic::Ordering::Relaxed), 0);
        command.prefix = Some(home.path().join("separate prefix"));
        assert!(execute(
            &command,
            identity,
            home.path(),
            &bootstrap,
            Some(bin.as_os_str()),
            &images
        )
        .is_err());
        assert_eq!(transport.0.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert!(!home.path().join("separate prefix").exists());
        assert_eq!(std::fs::read(foreign).unwrap(), b"foreign fixture");
    }
    #[test]
    fn update_version_order_prevents_downgrade_and_handles_release_candidates() {
        use std::cmp::Ordering::*;
        assert_eq!(selected_order("0.7.0", "0.6.9").unwrap(), Less);
        assert_eq!(selected_order("0.7.0", "0.7.0").unwrap(), Equal);
        assert_eq!(
            selected_order("0.7.0-rc.2", "0.7.0-rc.10").unwrap(),
            Greater
        );
        assert_eq!(selected_order("0.7.0-rc.10", "0.7.0").unwrap(), Greater);
        assert!(selected_order("0.7.0", "invalid").is_err());
    }
    fn args(s: &[&str]) -> Vec<OsString> {
        s.iter().map(OsString::from).collect()
    }
    #[test]
    fn managed_flags_preserve_hostnames() {
        assert!(parse(&args(&["install"])).unwrap().is_none());
        assert!(parse(&args(&["update"])).unwrap().is_none());
        let cmd = parse(&args(&[
            "--self-install",
            "--version",
            "0.7.0-rc.1",
            "--prefix",
            "/home/test/separate prefix",
        ]))
        .unwrap()
        .unwrap();
        assert!(!cmd.update);
        assert_eq!(cmd.version.as_deref(), Some("0.7.0-rc.1"));
        assert_eq!(
            cmd.prefix,
            Some(PathBuf::from("/home/test/separate prefix"))
        );
    }
    #[test]
    fn update_rejects_prefix_and_session_arguments() {
        assert!(parse(&args(&["--self-update", "--prefix", "/tmp/x"])).is_err());
        assert!(parse(&args(&["--self-update", "host"])).is_err());
        assert!(parse(&args(&["--self-install", "--self-update"])).is_err());
    }
}

#[cfg(test)]
mod signed_tests;
