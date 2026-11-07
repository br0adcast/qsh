//! `qshd transport-ensure`: the command line and its answer.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::{shell, BringUpError, Ready};

/// Same-account reported identity used to scope one busy-daemon choice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BusyDaemonIdentity {
    pub version: String,
    pub build: u64,
    pub checksum: String,
    pub pid: u32,
}

impl BusyDaemonIdentity {
    pub(crate) fn valid(&self) -> bool {
        self.version.len() <= 128 && !self.version.is_empty()
            && !self.version.chars().any(char::is_control)
            && self.checksum.len() == 64 && self.checksum.bytes().all(|b| b.is_ascii_hexdigit())
    }
}

/// A preflight decision, never daemon readiness or proof of compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BusyDaemonInfo {
    pub schema: u8,
    pub identity: BusyDaemonIdentity,
    pub active_connections: u64,
    pub transport_protocol: Option<u8>,
    pub required_protocol: u8,
}

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

pub(crate) fn command_for_policy(
    path: &str,
    name: &str,
    port: u16,
    client_pubkey: &[u8; 32],
    policy: &crate::InstallPolicy,
    report_busy: bool,
    accept_busy: Option<&BusyDaemonIdentity>,
) -> Result<String, BringUpError> {
    let mut command = command(path, name, port, client_pubkey);
    if matches!(policy, crate::InstallPolicy::RestartOnly) {
        command.push_str(" --restart-only");
    }
    if report_busy {
        command.push_str(" --report-busy");
    }
    if let Some(identity) = accept_busy {
        let json = serde_json::to_string(identity).map_err(|_| BringUpError::InvalidRequest("invalid busy identity".into()))?;
        command.push_str(" --accept-busy ");
        command.push_str(&shell::quote(&json));
    }
    Ok(command)
}

#[derive(Deserialize)]
struct ReadyBody {
    #[serde(default)]
    transport_protocol: Option<u8>,
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
    let count = |prefix: &str| out.lines().filter(|line| line.starts_with(prefix)).count();
    let busy_count = count("TRANSPORT-BUSY ");
    let ready_count = count("TRANSPORT-READY ");
    let key_count = count("server-pubkey: ");
    if busy_count != 0 {
        if busy_count != 1 || ready_count != 0 || key_count != 0 || out.lines().filter(|line| !line.trim().is_empty()).count() != 1 {
            return Err(bad("conflicting or duplicate startup results"));
        }
        let json = line_after(out, "TRANSPORT-BUSY ").unwrap();
        if json.len() > 4096 { return Err(bad("TRANSPORT-BUSY exceeds the decision limit")); }
        let info: BusyDaemonInfo = serde_json::from_str(json).map_err(|_| bad("invalid TRANSPORT-BUSY record"))?;
        if info.schema != 1 || info.active_connections == 0 || info.required_protocol == 0 || !info.identity.valid() {
            return Err(bad("invalid TRANSPORT-BUSY fields"));
        }
        return Err(BringUpError::BusyDaemon(info));
    }
    if ready_count != 1 || key_count != 1 {
        return Err(bad("missing or duplicate readiness records"));
    }
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
    if body.ports.is_empty() || body.ports.contains(&0) {
        return Err(bad("TRANSPORT-READY lists no ports"));
    }
    Ok(Ready {
        transport_protocol: body.transport_protocol,
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

    fn busy_json() -> serde_json::Value {
        serde_json::json!({"schema":1,"identity":{"version":"0.5.0","build":1,"checksum":"ab".repeat(32),"pid":42},"active_connections":2,"transport_protocol":null,"required_protocol":2})
    }

    #[test]
    fn busy_is_a_typed_decision_and_never_readiness() {
        let record = format!("TRANSPORT-BUSY {}\n", busy_json());
        let Err(BringUpError::BusyDaemon(info)) = parse(0, &record) else { panic!("expected typed Busy"); };
        assert_eq!(info.schema, 1);
        assert_eq!(info.identity.version, "0.5.0");
        assert_eq!(info.active_connections, 2);
        assert_eq!(info.transport_protocol, None);
        assert_eq!(info.required_protocol, 2);
        assert!(matches!(parse(1, &record), Err(BringUpError::EnsureFailed(_))));
    }

    #[test]
    fn busy_rejects_ambiguous_or_unbounded_decisions() {
        let busy = format!("TRANSPORT-BUSY {}\n", busy_json());
        for output in [format!("{busy}{busy}"), format!("{busy}{}", ready_out(r#"{"version":"0.6.0","ports":[60022]}"#)), format!("server-pubkey: {KEY_B64}\n{busy}")] {
            assert!(matches!(parse(0, &output), Err(BringUpError::BadReady(_))));
        }
        for (field, value) in [("schema", serde_json::json!(2)), ("active_connections", serde_json::json!(0)), ("required_protocol", serde_json::json!(0))] {
            let mut json = busy_json(); json[field] = value;
            assert!(matches!(parse(0, &format!("TRANSPORT-BUSY {json}")), Err(BringUpError::BadReady(_))));
        }
        for version in ["x".repeat(129), "bad\nversion".into()] {
            let mut json=busy_json(); json["identity"]["version"] = version.into();
            assert!(matches!(parse(0, &format!("TRANSPORT-BUSY {json}")), Err(BringUpError::BadReady(_))));
        }
        let mut json=busy_json(); json["identity"]["checksum"]="not-hex".into();
        assert!(matches!(parse(0, &format!("TRANSPORT-BUSY {json}")), Err(BringUpError::BadReady(_))));
        assert!(matches!(parse(0, &format!("TRANSPORT-BUSY {}", "x".repeat(4097))), Err(BringUpError::BadReady(_))));
        let ready=ready_out(r#"{"version":"0.6.0","ports":[60022]}"#);
        assert!(matches!(parse(0, &format!("{ready}{ready}")), Err(BringUpError::BadReady(_))));
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
                transport_protocol: None,
                server_pubkey: [7; 32],
                ports: vec![60000],
                version: "0.3.0".into(),
                warning: None
            }
        );
    }

    #[test]
    fn successful_bootstrap_retains_logging_warning_without_stderr() {
        let warning =
            "file logging disabled: opening daemon log /owned/qshd.log: Permission denied";
        let json = serde_json::json!({"version": "0.5.0", "ports": [60000], "warning": warning});
        let ready = parse(0, &ready_out(&json.to_string())).unwrap();
        assert_eq!(ready.warning.as_deref(), Some(warning));
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
