//! Finding `qshd` on the server: where the app puts it, else `$PATH`, else
//! where the project's docs install it.

/// Prints `os <uname -s>`, `arch <uname -m>`, `home <absolute HOME>`,
/// `service system` and/or
/// `service user` when a qshd service is running (systemd on Linux, launchd
/// on macOS; each probe is read-only, guarded by `command -v`, silent, and
/// prints nothing when it fails or its tool is absent; `launchctl print`
/// succeeds for a loaded service, not only a running one), one `cached <path>` per
/// runnable file named like a cached daemon, and `path <path>`: the one on
/// `$PATH` if there is one, else the first runnable file of a fixed list.
/// A non-interactive SSH session's `$PATH` often lacks where the project's
/// docs install qshd -- `~/.local/bin` (personal mode on Linux,
/// `docs/qshd-service.md`) and, on macOS, `/usr/local/bin` (README) -- so
/// those come first, then Homebrew on Apple silicon (`/opt/homebrew/bin`)
/// and `cargo install` (`~/.cargo/bin`). The choice is made in Rust, not in
/// the shell: version order and the arch names are easier to get right,
/// and to test, here.
pub(crate) const SCRIPT: &str = "case \"$HOME\" in /*) ;; *) exit 1 ;; esac; \
    case \"$HOME\" in *'\n'*|*'\r'*) exit 1 ;; esac; \
    os=$(uname -s) || exit $?; \
    arch=$(uname -m) || exit $?; \
    printf 'os %s\\narch %s\\nhome %s\\n' \"$os\" \"$arch\" \"$HOME\"; \
    if command -v systemctl >/dev/null 2>&1 \
    && systemctl is-active --quiet qshd.service >/dev/null 2>&1; \
    then printf 'service system\\n'; fi; \
    if command -v systemctl >/dev/null 2>&1 \
    && systemctl --user is-active --quiet qshd.service >/dev/null 2>&1; \
    then printf 'service user\\n'; fi; \
    if command -v launchctl >/dev/null 2>&1 \
    && launchctl print system/me.qsh.qshd >/dev/null 2>&1; \
    then printf 'service system\\n'; fi; \
    if command -v launchctl >/dev/null 2>&1 \
    && launchctl print \"gui/$(id -u)/me.qsh.qshd\" >/dev/null 2>&1; \
    then printf 'service user\\n'; fi; \
    for f in \"$HOME\"/.cache/qsh/qshd-*; do \
    if [ -f \"$f\" ] && [ -x \"$f\" ]; then printf 'cached %s\\n' \"$f\"; fi; done; \
    p=$(command -v qshd); \
    case \"$p\" in /*) printf 'path %s\\n' \"$p\" ;; \
    *) for p in \"$HOME\"/.local/bin/qshd /usr/local/bin/qshd /opt/homebrew/bin/qshd \
    \"$HOME\"/.cargo/bin/qshd; do \
    if [ -f \"$p\" ] && [ -x \"$p\" ]; then printf 'path %s\\n' \"$p\"; break; fi; done ;; \
    esac; exit 0";

/// Which kind of service runs qshd.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceKind {
    /// The system unit / launchd daemon (`qshd serve --system`).
    System,
    /// The account's own `qshd serve` service.
    User,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Located {
    Found(String),
    /// A qshd service already runs: nothing to start.
    Service(ServiceKind),
    Missing,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Probe {
    pub(crate) platform: crate::Platform,
    pub(crate) home: std::path::PathBuf,
    pub(crate) located: Located,
}

/// A failed or malformed lookup is never evidence that qshd is missing.
pub(crate) fn probe(code: i32, out: &str) -> Result<Probe, crate::BringUpError> {
    use crate::{BringUpError, Platform};
    let bad =
        |reason: &str| BringUpError::EnsureFailed(format!("the qshd lookup failed: {reason}"));
    if code != 0 {
        return Err(bad(&crate::ensure::excerpt(out, code)));
    }
    let mut os = None;
    let mut arch = None;
    let mut home = None;
    let mut cached = Vec::new();
    let mut on_path = None;
    let mut service = None;
    for line in out.lines().map(|line| line.trim_end_matches('\r')) {
        let (field, value) = line
            .split_once(' ')
            .ok_or_else(|| bad("malformed record"))?;
        if value.contains(['\r', '\0']) {
            return Err(bad("invalid record value"));
        }
        match field {
            "os" if os.is_none() => os = Some(value),
            "arch" if arch.is_none() => arch = Some(value),
            "home" if home.is_none() => home = Some(value),
            "path" if on_path.is_none() => {
                if !value.starts_with('/') {
                    return Err(bad("qshd path is not absolute"));
                }
                on_path = Some(value);
            }
            "cached" => {
                if !value.starts_with('/') {
                    return Err(bad("cached qshd path is not absolute"));
                }
                cached.push(value);
            }
            "service" => match value {
                "system" => service = Some(ServiceKind::System),
                "user" => service = service.or(Some(ServiceKind::User)),
                _ => return Err(bad("unknown service kind")),
            },
            _ => return Err(bad("unknown or duplicate record")),
        }
    }
    let platform = Platform::from_uname(
        os.ok_or_else(|| bad("missing OS"))?,
        arch.ok_or_else(|| bad("missing architecture"))?,
    )?;
    let home = home
        .filter(|home| home.starts_with('/'))
        .ok_or_else(|| bad("HOME is not absolute"))?;
    let newest = cached
        .into_iter()
        .filter_map(|path| cached_version(path, &platform).map(|version| (version, path)))
        .max_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, path)| path);
    let located = if let Some(service) = service {
        Located::Service(service)
    } else {
        newest
            .or(on_path)
            .map_or(Located::Missing, |path| Located::Found(path.into()))
    };
    Ok(Probe {
        platform,
        home: home.into(),
        located,
    })
}

fn cached_version(path: &str, platform: &crate::Platform) -> Option<semver::Version> {
    let name = path.rsplit('/').next()?;
    let suffix = platform.file_name("");
    let version = name
        .strip_prefix("qshd-")?
        .strip_suffix(suffix.strip_prefix("qshd-")?)?;
    crate::image::valid_version(version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BringUpError;

    fn output(extra: &str) -> String {
        format!("os Linux\narch x86_64\nhome /home/test account\n{extra}")
    }

    #[cfg(unix)]
    #[test]
    fn script_reports_home_and_detects_only_runnable_files() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("test account");
        let bin = temp.path().join("bin");
        std::fs::create_dir_all(home.join(".cache/qsh")).unwrap();
        std::fs::create_dir_all(&bin).unwrap();
        for (name, body) in [
            (
                "uname",
                "case \"$1\" in -s) echo Linux;; -m) echo x86_64;; esac",
            ),
            ("systemctl", "exit 1"),
            ("launchctl", "exit 1"),
            ("id", "echo 1000"),
        ] {
            let path = bin.join(name);
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let executable = home.join(".cache/qsh/qshd-0.4.0-x86_64");
        std::fs::write(&executable, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(home.join(".cache/qsh/qshd-9.0.0-x86_64"), "incomplete").unwrap();
        let output = std::process::Command::new("/bin/sh")
            .args(["-c", SCRIPT])
            .env_clear()
            .env("HOME", &home)
            .env("PATH", &bin)
            .env("XDG_CACHE_HOME", temp.path().join("cache"))
            .env("XDG_CONFIG_HOME", temp.path().join("config"))
            .env("HISTFILE", "/dev/null")
            .output()
            .unwrap();
        assert!(
            output.stderr.is_empty(),
            "unexpected shell stderr: {:?}",
            output.stderr
        );
        let found = probe(
            output.status.code().unwrap(),
            &String::from_utf8(output.stdout).unwrap(),
        )
        .unwrap();
        assert_eq!(found.home, home);
        assert_eq!(
            found.located,
            Located::Found(executable.to_str().unwrap().into())
        );
        for invalid_home in ["", "relative", "/first\npath /injected", "/bad\rname"] {
            let output = std::process::Command::new("/bin/sh")
                .args(["-c", SCRIPT])
                .env_clear()
                .env("HOME", invalid_home)
                .env("PATH", &bin)
                .env("HISTFILE", "/dev/null")
                .output()
                .unwrap();
            assert!(
                !output.status.success(),
                "HOME {invalid_home:?} was accepted"
            );
        }
    }

    #[test]
    fn probe_failure_is_not_missing() {
        for code in [-1, 1, 127] {
            assert!(matches!(
                probe(code, &output("")),
                Err(BringUpError::EnsureFailed(_))
            ));
        }
        assert_eq!(probe(0, &output("")).unwrap().located, Located::Missing);
    }

    #[test]
    fn probe_rejects_duplicate_platform_fields() {
        for extra in ["os Linux\n", "arch x86_64\n", "home /other\n"] {
            assert!(probe(0, &output(extra)).is_err(), "{extra:?}");
        }
    }

    #[test]
    fn probe_requires_complete_valid_platform_and_absolute_single_line_home() {
        for out in [
            "arch x86_64\nhome /h\n",
            "os Linux\nhome /h\n",
            "os Linux\narch x86_64\n",
            "os Linux\narch x86_64\nhome \n",
            "os Linux\narch x86_64\nhome relative\n",
            "os Linux\narch x86_64\nhome /first\nsecond\n",
            "os Linux\narch x86_64\nhome /bad\rname\n",
            "os Linux\narch riscv64\nhome /h\n",
            "os FreeBSD\narch x86_64\nhome /h\n",
            "os Linux\narch x86_64\nhome /h\nservice unknown\n",
        ] {
            assert!(probe(0, out).is_err(), "{out:?}");
        }
        let result = probe(0, &output("path /home/test account/bin/qshd\n")).unwrap();
        assert_eq!(result.home, std::path::PathBuf::from("/home/test account"));
        assert_eq!(
            result.located,
            Located::Found("/home/test account/bin/qshd".into())
        );
    }

    #[test]
    fn darwin_never_selects_linux_cache() {
        let out = "os Darwin\narch arm64\nhome /h\ncached /h/.cache/qsh/qshd-99.0.0-aarch64\ncached /h/.cache/qsh/qshd-0.4.0-aarch64-darwin\n";
        assert_eq!(
            probe(0, out).unwrap().located,
            Located::Found("/h/.cache/qsh/qshd-0.4.0-aarch64-darwin".into())
        );
        assert_eq!(
            probe(
                0,
                "os Darwin\narch arm64\nhome /h\ncached /h/.cache/qsh/qshd-99.0.0-aarch64\n"
            )
            .unwrap()
            .located,
            Located::Missing
        );
    }

    #[test]
    fn ready_cache_names_are_complete_semver_and_sorted_by_precedence() {
        for (files, expected) in [
            (
                "cached /h/qshd-0.9.0-x86_64\ncached /h/qshd-0.10.0-x86_64\n",
                "/h/qshd-0.10.0-x86_64",
            ),
            (
                "cached /h/qshd-0.4.0-rc.2-x86_64\ncached /h/qshd-0.4.0-rc.10-x86_64\n",
                "/h/qshd-0.4.0-rc.10-x86_64",
            ),
            (
                "cached /h/qshd-0.4.0-rc.10-x86_64\ncached /h/qshd-0.4.0-x86_64\n",
                "/h/qshd-0.4.0-x86_64",
            ),
        ] {
            assert_eq!(
                probe(0, &output(files)).unwrap().located,
                Located::Found(expected.into())
            );
        }
        let files = "cached /h/qshd-9.0.0-x86_64.new\ncached /h/qshd-9.0-x86_64\ncached /h/qshd-9.0.0+build-x86_64\ncached /h/qshd-9.0.0-aarch64\npath /usr/bin/qshd\n";
        assert_eq!(
            probe(0, &output(files)).unwrap().located,
            Located::Found("/usr/bin/qshd".into())
        );
    }

    #[test]
    fn system_service_wins_over_user_and_binary() {
        for services in [
            "service system\nservice user\n",
            "service user\nservice system\n",
        ] {
            let out = output(&format!(
                "{services}cached /h/qshd-0.4.0-x86_64\npath /usr/bin/qshd\n"
            ));
            assert_eq!(
                probe(0, &out).unwrap().located,
                Located::Service(ServiceKind::System)
            );
        }
        assert_eq!(
            probe(0, &output("service user\n")).unwrap().located,
            Located::Service(ServiceKind::User)
        );
    }

    #[test]
    fn probe_rejects_malformed_paths_and_unknown_records() {
        for line in [
            "path relative\n",
            "cached relative\n",
            "path /one\npath /two\n",
            "garbage\n",
        ] {
            assert!(probe(0, &output(line)).is_err(), "{line:?}");
        }
    }

    #[test]
    fn carriage_return_line_endings_are_supported() {
        let out = "os Linux\r\narch arm64\r\nhome /h\r\ncached /h/qshd-0.4.0-aarch64\r\n";
        assert_eq!(
            probe(0, out).unwrap().located,
            Located::Found("/h/qshd-0.4.0-aarch64".into())
        );
    }
}
