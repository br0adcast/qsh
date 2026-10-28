#![forbid(unsafe_code)]

//! Shared logging for `qsh` and `qshd`: one line format, a rotating file
//! sink and a `log::Log` with a per-component filter. Logging is best
//! effort: it never panics and never reports write errors.

pub mod authority;
mod diagnostic;
mod file;
mod file_path;
mod format;
mod logger;

pub use diagnostic::{diagnostic, path_error};
pub use file::FileSink;
pub use format::{breaks_the_line, component_of, format_lines};

/// Which records are kept: a default level and per-component overrides
/// (a component is the first path segment of the record's target).
pub struct Filter {
    pub default: log::LevelFilter,
    pub per_component: Vec<(String, log::LevelFilter)>,
}

/// Installs the global logger writing through `sink`; returns false when a
/// logger is already installed (then nothing changes).
pub fn install(sink: FileSink, filter: Filter) -> bool {
    let logger = logger::Logger::new(sink, filter);
    let max = logger.max_level();
    if log::set_boxed_logger(Box::new(logger)).is_err() {
        return false;
    }
    log::set_max_level(max);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use log::{Level, LevelFilter};
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn known_instant_formats() {
        let at = UNIX_EPOCH + Duration::from_millis(1_790_799_757_123);
        let l = format_lines(at, 42, Level::Info, "transport", "hello");
        assert_eq!(
            l,
            vec!["2026-09-30 20:22:37.123 UTC [42] INFO  transport: hello"]
        );
    }

    #[test]
    fn leap_day() {
        let at = UNIX_EPOCH + Duration::from_millis(1_709_210_096_005);
        let l = format_lines(at, 1, Level::Error, "x", "y");
        assert_eq!(l, vec!["2024-02-29 12:34:56.005 UTC [1] ERROR x: y"]);
    }

    #[test]
    fn date_algorithm_pins() {
        let f = |secs: u64| {
            format_lines(
                UNIX_EPOCH + Duration::from_secs(secs),
                1,
                Level::Info,
                "c",
                "t",
            )[0]
            .clone()
        };
        assert!(f(951_782_400).starts_with("2000-02-29 00:00:00.000 UTC"));
        assert!(f(4_107_542_400).starts_with("2100-03-01 00:00:00.000 UTC"));
        let before = UNIX_EPOCH - Duration::from_secs(5);
        let l = format_lines(before, 1, Level::Info, "c", "t");
        assert!(l[0].starts_with("1970-01-01 00:00:00.000 UTC"));
    }

    #[test]
    fn existing_loose_modes_are_tightened() {
        let d = crate::private_test_dir().unwrap();
        let dir = d.path().join("log");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let p = dir.join("a.log");
        std::fs::write(&p, b"old\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(FileSink::open_in_private_dir(&p, 1000).is_some());
        let m = |x: &std::path::Path| std::fs::metadata(x).unwrap().permissions().mode() & 0o777;
        assert_eq!(m(&p), 0o600);
        assert_eq!(m(&dir), 0o700);
    }

    #[test]
    fn levels_are_padded() {
        let l = |lv| format_lines(UNIX_EPOCH, 1, lv, "c", "t")[0].clone();
        assert!(l(Level::Warn).contains("] WARN  c: t"));
        assert!(l(Level::Debug).contains("] DEBUG c: t"));
        assert!(l(Level::Trace).contains("] TRACE c: t"));
        assert!(l(Level::Info).starts_with("1970-01-01 00:00:00.000 UTC [1] INFO "));
    }

    #[test]
    fn component_of_cases() {
        assert_eq!(component_of("transport::driver_std"), "transport");
        assert_eq!(component_of("qsh"), "qsh");
        assert_eq!(component_of(""), "?");
    }

    #[test]
    fn multiline_repeats_header() {
        let l = format_lines(UNIX_EPOCH, 7, Level::Info, "c", "a\nb\r\nc");
        assert_eq!(l.len(), 3);
        let header = "1970-01-01 00:00:00.000 UTC [7] INFO  c: ";
        assert_eq!(
            l,
            vec![
                format!("{header}a"),
                format!("{header}b"),
                format!("{header}c")
            ]
        );
    }

    #[test]
    fn control_chars_replaced_tab_kept() {
        let l = format_lines(UNIX_EPOCH, 1, Level::Info, "c", "a\x1b[31mb\tc\x07");
        assert!(l[0].ends_with("c: a?[31mb\tc?"), "{:?}", l[0]);
        // NEL, the line separator and the paragraph separator: one line, each a '?'.
        let l = format_lines(
            UNIX_EPOCH,
            1,
            Level::Info,
            "c",
            "a\u{85}b\u{2028}c\u{2029}d",
        );
        assert_eq!(l.len(), 1, "{l:?}");
        assert!(l[0].ends_with("c: a?b?c?d"), "{:?}", l[0]);
    }

    fn lines_of(p: &std::path::Path) -> Vec<String> {
        std::fs::read_to_string(p)
            .unwrap_or_default()
            .lines()
            .map(String::from)
            .collect()
    }

    #[test]
    fn rotates_past_max_bytes() {
        let d = crate::private_test_dir().unwrap();
        let p = d.path().join("log").join("a.log");
        let s = FileSink::open(&p, 200).unwrap();
        let line = "x".repeat(60);
        for i in 0..6 {
            s.write_lines(&[format!("{i}{line}")]);
        }
        let rotated = d.path().join("log").join("a.log.1");
        assert!(rotated.exists());
        let cur = lines_of(&p);
        assert!(!cur.is_empty() && cur.len() < 6);
        assert!(cur.last().unwrap().starts_with('5'));
    }

    #[test]
    fn open_under_a_file_is_none() {
        let d = crate::private_test_dir().unwrap();
        let f = d.path().join("f");
        std::fs::write(&f, b"x").unwrap();
        assert!(FileSink::open(&f.join("sub").join("a.log"), 100).is_none());
    }

    #[test]
    fn permissions() {
        let d = crate::private_test_dir().unwrap();
        let p = d.path().join("newdir").join("a.log");
        let s = FileSink::open(&p, 1000).unwrap();
        s.write_lines(&["hi".into()]);
        let fm = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        let dm = std::fs::metadata(p.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(fm, 0o600);
        assert_eq!(dm, 0o700);
        assert!(s.try_clone_file().is_some());
    }

    #[test]
    fn two_sinks_two_threads_keep_lines_whole() {
        let d = crate::private_test_dir().unwrap();
        let p = d.path().join("a.log");
        let mk = |tag: &'static str| {
            let s = FileSink::open(&p, 4000).unwrap();
            std::thread::spawn(move || {
                for i in 0..500 {
                    s.write_lines(&[format!(
                        "2026-09-30 20:22:37.123 UTC [1] INFO  {tag}: line {i} {}",
                        "z".repeat(40)
                    )]);
                }
            })
        };
        let (a, b) = (mk("a"), mk("b"));
        a.join().unwrap();
        b.join().unwrap();
        let mut n = 0;
        for f in [p.clone(), d.path().join("a.log.1")] {
            for l in lines_of(&f) {
                n += 1;
                assert!(l.starts_with("2026-09-30 "), "torn line: {l:?}");
                assert!(l.ends_with(&"z".repeat(40)), "torn line: {l:?}");
            }
        }
        assert!(n > 0);
        assert!(d.path().join("a.log.1").exists());
    }

    #[test]
    fn filter_per_component() {
        let f = Filter {
            default: LevelFilter::Info,
            per_component: vec![("russh".into(), LevelFilter::Warn)],
        };
        let lg = crate::logger::Logger::for_test(f);
        use log::Log;
        fn md(t: &str, l: Level) -> log::Metadata<'_> {
            log::Metadata::builder().target(t).level(l).build()
        }
        assert!(!lg.enabled(&md("russh::client", Level::Info)));
        assert!(lg.enabled(&md("russh::client", Level::Warn)));
        assert!(lg.enabled(&md("transport", Level::Info)));
        assert!(!lg.enabled(&md("transport", Level::Debug)));
    }

    #[test]
    fn install_once_writes_and_second_returns_false() {
        let d = crate::private_test_dir().unwrap();
        let p = d.path().join("i.log");
        let s = FileSink::open(&p, 10_000).unwrap();
        let f = || Filter {
            default: LevelFilter::Info,
            per_component: vec![],
        };
        assert!(install(s, f()));
        log::info!(target: "transport::x", "hello world");
        log::debug!(target: "transport::x", "hidden");
        assert!(!install(FileSink::open(&p, 10_000).unwrap(), f()));
        let got = lines_of(&p);
        assert_eq!(got.len(), 1, "{got:?}");
        assert!(got[0].contains("INFO  transport: hello world"));
    }
}

#[cfg(test)]
mod file_path_tests;

#[cfg(test)]
fn private_test_dir() -> std::io::Result<tempfile::TempDir> {
    use std::os::unix::fs::PermissionsExt;
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
}

#[cfg(test)]
mod diagnostic_tests {
    #[test]
    fn diagnostics_preserve_permission_and_io_error_kinds_with_component() {
        for kind in [
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::StorageFull,
        ] {
            let error = super::path_error(
                std::path::Path::new("component\nname"),
                "opening log",
                kind.into(),
            );
            assert_eq!(error.kind(), kind);
            assert!(error.to_string().contains("component\\nname"));
            assert!(!error.to_string().contains('\n'));
        }
    }

    #[test]
    fn diagnostics_preserve_non_utf8_path_bytes_without_terminal_controls() {
        use std::os::unix::ffi::OsStringExt;
        let path = std::path::PathBuf::from(std::ffi::OsString::from_vec(b"raw-\xff\n".to_vec()));
        let error = super::path_error(
            &path,
            "opening",
            std::io::ErrorKind::PermissionDenied.into(),
        );
        let message = error.to_string();
        assert!(
            message.contains("\\x") && message.contains("\\n"),
            "{message}"
        );
        assert!(!message.contains('\u{fffd}') && !message.contains('\n'));
    }

    #[test]
    fn diagnostics_escape_controls_and_bound_multibyte_output() {
        let message = super::diagnostic(&format!("a\n\x1b\u{202e}{}", "🦀".repeat(2048)));
        assert!(message.starts_with("a\\n\\u{1b}\\u{202e}"));
        assert!(message.len() <= 1024);
        assert!(message.ends_with("[truncated]"));
        assert!(!message.chars().any(char::is_control));
    }
}
