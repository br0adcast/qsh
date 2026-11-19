// The replacement's log lines: what `restart` writes is what
// `RestartLogFacts` reads, in the daemon log's real line format.

fn update_line(level: crate::log::Level, component: &str, text: &str) -> String {
    let mut lines =
        logging::format_lines(std::time::SystemTime::now(), 4242, level, component, text);
    assert_eq!(lines.len(), 1);
    lines.pop().unwrap()
}

#[test]
fn restart_log_tokens_are_distinct_single_words() {
    let mut tokens: Vec<&str> = RestartStep::ALL.iter().map(|step| step.token()).collect();
    tokens.extend(RestartStop::ALL.iter().map(|stop| stop.token()));
    for token in &tokens {
        assert!(!token.is_empty() && !token.contains(' '), "{token}");
    }
    let mut unique = tokens.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), tokens.len());
    assert!(!RESTART_STEP_LOG.starts_with(RESTART_STOP_LOG));
    assert!(!RESTART_STOP_LOG.starts_with(RESTART_STEP_LOG));
}

#[test]
fn restart_log_facts_read_every_step_and_stop_as_written() {
    for step in RestartStep::ALL {
        for detail in ["", "replacing this process with build 7"] {
            let line = update_line(
                crate::log::Level::Info,
                "update",
                &restart_text(RESTART_STEP_LOG, step.token(), detail),
            );
            let facts = RestartLogFacts::parse(line.as_bytes());
            assert_eq!(facts.steps, vec![step.token()]);
            assert_eq!(facts.last_step, Some(step.token()));
            assert_eq!(facts.stopped, None);
            assert!(!facts.unrecognized);
        }
    }
    for stop in RestartStop::ALL {
        let line = update_line(
            crate::log::Level::Warn,
            "update",
            &restart_text(RESTART_STOP_LOG, stop.token(), "a detail -- with dashes"),
        );
        let facts = RestartLogFacts::parse(line.as_bytes());
        assert_eq!(facts.stopped, Some(stop.token()));
        assert!(facts.steps.is_empty());
        assert!(!facts.unrecognized);
    }
}

#[test]
fn restart_log_facts_follow_a_whole_attempt_and_the_new_image() {
    let log = [
        update_line(crate::log::Level::Info, "qshd", "started"),
        update_line(
            crate::log::Level::Info,
            "update",
            &restart_text(RESTART_STEP_LOG, "announced", ""),
        ),
        update_line(
            crate::log::Level::Warn,
            "update",
            &restart_text(RESTART_STEP_LOG, "join-late", "not every session"),
        ),
        update_line(
            crate::log::Level::Info,
            "update",
            &restart_text(RESTART_STEP_LOG, "drained", ""),
        ),
        update_line(
            crate::log::Level::Info,
            "update",
            &restart_text(RESTART_STEP_LOG, "announced", ""),
        ),
        update_line(
            crate::log::Level::Info,
            "update",
            &format!("{RESUMED_LOG}: pid=1 build=2"),
        ),
        update_line(
            crate::log::Level::Error,
            "update",
            &format!("{RESUME_FAILED_LOG}: no handover"),
        ),
    ]
    .join("\n");
    let facts = RestartLogFacts::parse(log.as_bytes());
    assert_eq!(facts.steps, vec!["announced", "join-late", "drained"]);
    assert_eq!(facts.last_step, Some("announced"));
    assert!(facts.resumed && facts.resume_failed);
    assert_eq!(facts.stopped, None);
    assert!(!facts.unrecognized);
}

#[test]
fn restart_log_facts_refuse_what_they_cannot_name() {
    // Nothing at all, and lines cut at either end or not text.
    assert_eq!(RestartLogFacts::parse(b""), RestartLogFacts::default());
    let whole = update_line(
        crate::log::Level::Info,
        "update",
        &restart_text(RESTART_STEP_LOG, "exec", ""),
    );
    let cut = &whole.as_bytes()[whole.len() / 2..];
    assert_eq!(RestartLogFacts::parse(cut), RestartLogFacts::default());
    let mut binary = b"\xff\xfe".to_vec();
    binary.extend_from_slice(whole.as_bytes());
    assert_eq!(RestartLogFacts::parse(&binary), RestartLogFacts::default());
    // The same words from another component are not the replacement's.
    let other = update_line(
        crate::log::Level::Info,
        "worker",
        &restart_text(RESTART_STEP_LOG, "exec", ""),
    );
    assert_eq!(
        RestartLogFacts::parse(other.as_bytes()),
        RestartLogFacts::default()
    );
    // An unknown token is reported as such, never as a step or a stop, and
    // its text is not kept.
    for prefix in [RESTART_STEP_LOG, RESTART_STOP_LOG] {
        let line = update_line(
            crate::log::Level::Warn,
            "update",
            &restart_text(prefix, "PRIVATE_CANARY", ""),
        );
        let facts = RestartLogFacts::parse(line.as_bytes());
        assert!(facts.unrecognized);
        assert!(facts.steps.is_empty() && facts.stopped.is_none());
        assert!(!serde_json::to_string(&facts)
            .unwrap()
            .contains("PRIVATE_CANARY"));
    }
}

#[test]
fn restart_stopped_returns_its_result_unchanged() {
    let result = UpdateResult::Rejected {
        code: RejectCode::ControlBusy,
        detail: "busy".into(),
    };
    assert_eq!(
        restart_stopped(RestartStop::ControlBusy, result.clone()),
        result
    );
    assert_eq!(
        restart_stopped(RestartStop::Revoked, UpdateResult::Restarting),
        UpdateResult::Restarting
    );
}
