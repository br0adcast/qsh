//! `qshd transport-ensure`: the command line and its answer.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::Deserialize;

use crate::{shell, BringUpError, Ready};

/// How much of a failed command's output a person gets to read.
pub(crate) const ERROR_TEXT_MAX: usize = crate::exec::MAX_DIAGNOSTIC;

pub(crate) fn command(path: &str, name: &str, port: u16, client_pubkey: &[u8; 32]) -> String {
    format!(
        "{} transport-ensure --name {} --port {port} --client-pubkey {}",
        shell::quote(path),
        shell::quote(name),
        shell::quote(&BASE64.encode(client_pubkey)),
    )
}

#[derive(Deserialize)]
struct ReadyBody {
    version: String,
    ports: Vec<u16>,
    #[serde(default)]
    warning: Option<String>,
}

pub(crate) fn parse(code: i32, out: &str) -> Result<Ready, BringUpError> {
    if code != 0 {
        return Err(BringUpError::EnsureFailed(format!(
            "qshd transport-ensure failed: {}",
            excerpt(out, code)
        )));
    }
    let bad = |what: &str| BringUpError::BadReady(format!("{what}: {}", excerpt(out, code)));
    // The verified SSH login reports the intended daemon identity here.
    // Callers bind it to their endpoint; Noise must still prove possession.
    let key = line_after(out, "server-pubkey: ").ok_or_else(|| bad("no server-pubkey line"))?;
    let server_pubkey = BASE64
        .decode(key.trim())
        .ok()
        .and_then(|key| key.try_into().ok())
        .ok_or_else(|| bad("the server-pubkey line is not a 32-byte key"))?;
    let json = line_after(out, "TRANSPORT-READY ").ok_or_else(|| bad("no TRANSPORT-READY line"))?;
    let body: ReadyBody = serde_json::from_str(json.trim()).map_err(|error| {
        // Displaying a serde data error can repeat the entire rejected string.
        // Report its bounded location/category; the output excerpt follows.
        bad(&format!(
            "TRANSPORT-READY does not parse ({:?} at line {}, column {})",
            error.classify(),
            error.line(),
            error.column()
        ))
    })?;
    if body.ports.is_empty() {
        return Err(bad("TRANSPORT-READY lists no ports"));
    }
    Ok(Ready {
        server_pubkey,
        ports: body.ports,
        version: body.version,
        warning: body.warning,
    })
}

fn line_after<'a>(out: &'a str, prefix: &str) -> Option<&'a str> {
    out.lines()
        .map(|l| l.trim_end_matches('\r'))
        .find_map(|l| l.strip_prefix(prefix))
}

/// `out` trimmed and cut to `ERROR_TEXT_MAX`, or the exit code if empty.
pub(crate) fn excerpt(out: &str, code: i32) -> String {
    let text = out.trim();
    if text.is_empty() {
        return format!("exit code {code}");
    }
    crate::exec::escaped(text, ERROR_TEXT_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_B64: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";

    fn ready_out(json: &str) -> String {
        format!("banner\nserver-pubkey: {KEY_B64}\r\nTRANSPORT-READY {json}\n")
    }

    #[test]
    fn the_command_names_the_label_the_port_and_the_key() {
        assert_eq!(
            command("/h/.cache/qsh/qshd-0.3.0-x86_64", "console", 60022, &[7u8; 32]),
            format!("'/h/.cache/qsh/qshd-0.3.0-x86_64' transport-ensure --name 'console' --port 60022 --client-pubkey '{KEY_B64}'")
        );
    }

    #[test]
    fn ready_retains_noise_key_without_trusting_it() {
        let ready = parse(0, &ready_out(r#"{"version":"0.4.0","ports":[60022]}"#)).unwrap();
        assert_eq!(ready.server_pubkey, [7; 32]);
    }

    #[test]
    fn the_command_quotes_the_requested_name() {
        let result = command("/tmp/qshd", "phone's name", 60022, &[7; 32]);
        assert!(
            result.contains(r"--name 'phone'\''s name' --port 60022"),
            "{result}"
        );
    }

    #[test]
    fn a_ready_answer_parses() {
        let r = parse(
            0,
            &ready_out(r#"{"version":"0.3.0","ports":[60000],"warning":null,"pid":5}"#),
        )
        .unwrap();
        assert_eq!(
            r,
            Ready {
                server_pubkey: [7; 32],
                ports: vec![60000],
                version: "0.3.0".into(),
                warning: None
            }
        );
    }

    #[test]
    fn a_warning_is_kept() {
        let r = parse(
            0,
            &ready_out(r#"{"version":"0.3.0","ports":[60000],"warning":"daemon differs"}"#),
        )
        .unwrap();
        assert_eq!(r.warning.as_deref(), Some("daemon differs"));
    }

    #[test]
    fn a_missing_warning_is_none() {
        let r = parse(0, &ready_out(r#"{"version":"0.3.0","ports":[60000]}"#)).unwrap();
        assert_eq!(r.warning, None);
    }

    #[test]
    fn a_failed_run_carries_its_own_words() {
        match parse(3, "  qshd: port 60022 is already taken\n") {
            Err(BringUpError::EnsureFailed(t)) => {
                assert_eq!(
                    t,
                    "qshd transport-ensure failed: qshd: port 60022 is already taken"
                )
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_silent_failure_names_the_exit_code() {
        match parse(127, "") {
            Err(BringUpError::EnsureFailed(t)) => assert!(t.ends_with("exit code 127"), "{t}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_long_failure_is_cut() {
        let long = "x".repeat(5000);
        match parse(1, &long) {
            Err(BringUpError::EnsureFailed(t)) => {
                assert!(
                    t.chars().count()
                        <= "qshd transport-ensure failed: ".len() + ERROR_TEXT_MAX + 1,
                    "{}",
                    t.len()
                );
                assert!(t.ends_with('…'));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn success_without_the_lines_is_bad_ready() {
        assert!(matches!(
            parse(0, "hello\n"),
            Err(BringUpError::BadReady(_))
        ));
    }

    #[test]
    fn a_short_server_key_is_bad_ready() {
        let o = "server-pubkey: AAAA\nTRANSPORT-READY {\"version\":\"0.3.0\",\"ports\":[1]}\n";
        assert!(matches!(parse(0, o), Err(BringUpError::BadReady(_))));
    }

    #[test]
    fn no_ports_is_bad_ready() {
        assert!(matches!(
            parse(0, &ready_out(r#"{"version":"0.3.0","ports":[]}"#)),
            Err(BringUpError::BadReady(_))
        ));
    }

    #[test]
    fn broken_json_is_bad_ready() {
        assert!(matches!(
            parse(0, &ready_out("{nope")),
            Err(BringUpError::BadReady(_))
        ));
    }
}

#[cfg(test)]
mod diagnostic_tests {
    #[test]
    fn failed_command_controls_cannot_reach_the_terminal() {
        let error = super::parse(1, "\x1b[31mdenied\r\x07")
            .unwrap_err()
            .to_string();
        assert!(!error.chars().any(char::is_control), "{error:?}");
        assert!(error.contains("denied"));
    }
}

#[cfg(test)]
mod malformed_diagnostic_tests {
    #[test]
    fn rejected_json_values_cannot_expand_the_error_without_bound() {
        let output = format!("server-pubkey: BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=\nTRANSPORT-READY {{\"version\":\"0.5.0\",\"ports\":\"{}\"}}\n", "x".repeat(8000));
        let error = super::parse(0, &output).unwrap_err().to_string();
        assert!(
            error.chars().count() <= 1200,
            "diagnostic has {} characters",
            error.chars().count()
        );
        assert!(!error.chars().any(char::is_control));
    }
}
