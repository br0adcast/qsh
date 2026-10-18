//! One command over the SSH connection: its output, its exit code, and
//! nothing that can hang past a deadline or a cancel.

use std::collections::{HashMap, VecDeque};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use client::channel::{ChannelSubstrate, SubstrateEvent};
use transport::channel::{ChannelKind, OpenRequest};

use crate::{shell, BringUpError};

/// Enough for any real answer; a flood beyond it is read and dropped.
pub(crate) const MAX_OUTPUT: usize = 64 * 1024;
const MAX_STDERR: usize = 16 * 1024;
pub(crate) const MAX_DIAGNOSTIC: usize = 1000;

/// Wait for the connection watchdog after an exit without a status.
pub(crate) const CLOSED_GRACE: Duration = Duration::from_secs(1);
const MAX_TERMINAL_EVENTS: usize = 256;

pub(crate) enum Event {
    Channel(SubstrateEvent),
    Closed(String),
}

#[derive(Default)]
struct Buffered {
    output: HashMap<u8, Output>,
    output_len: usize,
    stderr_len: usize,
    terminal: VecDeque<Event>,
    closed: Option<String>,
    disconnected: bool,
    active: Option<u8>,
}

#[derive(Default)]
struct Shared {
    buffered: Mutex<Buffered>,
    changed: Condvar,
}

/// Incoming data is accumulated once, independently of terminal events.
pub(crate) struct Collector(Arc<Shared>, Arc<dyn crate::BringUpObserver>);
pub(crate) struct Events(Arc<Shared>);

pub(crate) fn collector(observer: Arc<dyn crate::BringUpObserver>) -> (Collector, Events) {
    let shared = Arc::new(Shared::default());
    (Collector(Arc::clone(&shared), observer), Events(shared))
}

impl Buffered {
    fn append(&mut self, ch: u8, bytes: &[u8], stderr: bool) {
        if bytes.is_empty() || self.active.is_some_and(|stream| stream != ch) {
            return;
        }
        let (used, limit) = if stderr {
            (&mut self.stderr_len, MAX_STDERR)
        } else {
            (&mut self.output_len, MAX_OUTPUT)
        };
        let keep = bytes.len().min(limit - *used);
        // Retain truncation even when another pre-prepare stream used all space.
        let output = self.output.entry(ch).or_default();
        let (buffer, truncated) = if stderr {
            (&mut output.stderr, &mut output.stderr_truncated)
        } else {
            (&mut output.stdout, &mut output.stdout_truncated)
        };
        buffer.extend_from_slice(&bytes[..keep]);
        *truncated |= keep < bytes.len();
        *used += keep;
    }
}

impl Collector {
    fn send(&self, event: Event) {
        let mut state = self.0.buffered.lock().unwrap();
        match event {
            Event::Channel(SubstrateEvent::Data { ch, bytes }) => {
                state.append(ch, &bytes, false);
            }
            Event::Channel(SubstrateEvent::ExtendedData {
                ch,
                data_type: 1,
                bytes,
            }) => {
                state.append(ch, &bytes, true);
            }
            Event::Channel(SubstrateEvent::ExtendedData { ch, data_type, .. }) => {
                if state.active.is_none_or(|stream| stream == ch) {
                    // One scalar per u8 stream, never one completion event per packet.
                    state
                        .output
                        .entry(ch)
                        .or_default()
                        .unsupported_type
                        .get_or_insert(data_type);
                }
            }
            Event::Closed(reason) => {
                if state.closed.is_none() {
                    state.closed = Some(reason);
                }
            }
            event => {
                if state.terminal.len() < MAX_TERMINAL_EVENTS {
                    state.terminal.push_back(event);
                } else if state.closed.is_none() {
                    state.closed = Some("resource limit: too many SSH command events".into());
                }
            }
        }
        self.0.changed.notify_one();
    }
}

impl Drop for Collector {
    fn drop(&mut self) {
        self.0.buffered.lock().unwrap().disconnected = true;
        self.0.changed.notify_one();
    }
}

impl ssh::SshEvents for Collector {
    fn on_connect_stage(&self, stage: ssh::SshConnectStage) {
        let stage = match stage {
            ssh::SshConnectStage::Knocking => crate::BringUpStage::Knocking,
            ssh::SshConnectStage::Connecting => crate::BringUpStage::Connecting,
        };
        self.1.on_progress(crate::BringUpProgress {
            stage,
            completed: 0,
            total: None,
            finished: false,
        });
    }

    fn on_channel(&self, event: SubstrateEvent) {
        self.send(Event::Channel(event));
    }
    fn on_closed(&self, reason: String) {
        self.send(Event::Closed(reason));
    }
}

impl Events {
    fn prepare(&self, stream: u8) {
        let mut state = self.0.buffered.lock().unwrap();
        state.active = Some(stream);
        state.output.retain(|ch, _| *ch == stream);
        state.output_len = state.output.values().map(|out| out.stdout.len()).sum();
        state.stderr_len = state.output.values().map(|out| out.stderr.len()).sum();
        state.terminal.retain(|e| matches!(e, Event::Channel(SubstrateEvent::Exit { ch, .. } | SubstrateEvent::Refused { ch, .. }) if *ch == stream));
    }

    fn take_output(&self, stream: u8) -> Output {
        let mut state = self.0.buffered.lock().unwrap();
        let output = state.output.remove(&stream).unwrap_or_default();
        state.output_len -= output.stdout.len();
        state.stderr_len -= output.stderr.len();
        output
    }

    fn recv_timeout(&self, timeout: Duration) -> Result<Event, RecvTimeoutError> {
        let state = self.0.buffered.lock().unwrap();
        let (mut state, _) = self
            .0
            .changed
            .wait_timeout_while(state, timeout, |s| {
                s.closed.is_none() && s.terminal.is_empty() && !s.disconnected
            })
            .unwrap();
        if let Some(reason) = state.closed.take() {
            return Ok(Event::Closed(reason));
        }
        if let Some(event) = state.terminal.pop_front() {
            return Ok(event);
        }
        Err(if state.disconnected {
            RecvTimeoutError::Disconnected
        } else {
            RecvTimeoutError::Timeout
        })
    }
}

#[derive(Debug, Default)]
pub(crate) struct Output {
    /// `-1` when the server sent no exit status.
    pub(crate) code: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_truncated: bool,
    stderr_truncated: bool,
    unsupported_type: Option<u32>,
}

impl Output {
    /// Machine parsers must not accept a retained prefix or lossy decoding.
    pub(crate) fn complete_stdout(&self) -> Result<&str, String> {
        if self.stdout_truncated {
            return Err(format!("stdout was truncated: {}", self.diagnostic()));
        }
        std::str::from_utf8(&self.stdout)
            .map_err(|_| format!("stdout is not valid UTF-8: {}", self.diagnostic()))
    }

    pub(crate) fn failure(&self, what: &str) -> BringUpError {
        BringUpError::EnsureFailed(format!(
            "{what} failed (exit {}): {}",
            self.code,
            self.diagnostic()
        ))
    }

    /// A single combined budget, with diagnostic stderr first. Mark retention
    /// loss before the excerpt so a flood cannot hide its truncation flag.
    fn diagnostic(&self) -> String {
        self.diagnostic_streams(true)
    }

    fn diagnostic_streams(&self, include_stdout: bool) -> String {
        let mut text = String::new();
        for (label, bytes, truncated) in [
            ("stderr", &self.stderr, self.stderr_truncated),
            ("stdout", &self.stdout, self.stdout_truncated),
        ] {
            if (!include_stdout && label == "stdout") || (bytes.is_empty() && !truncated) {
                continue;
            }
            if !text.is_empty() {
                text.push_str("; ");
            }
            text.push_str(label);
            if truncated {
                text.push_str(" (truncated)");
            }
            text.push_str(": ");
            text.push_str(&escaped(&String::from_utf8_lossy(bytes), MAX_DIAGNOSTIC));
            text = escaped(&text, MAX_DIAGNOSTIC);
            if text.chars().count() >= MAX_DIAGNOSTIC {
                break;
            }
        }
        text
    }
}

/// Escape terminal controls before applying the displayed character limit.
/// Do not allocate a second, unbounded escaped copy of hostile output.
pub(crate) fn escaped(text: &str, limit: usize) -> String {
    let mut out = String::new();
    let mut count = 0;
    for ch in text.chars() {
        let escaped = if ch.is_control() {
            ch.escape_default().to_string()
        } else {
            ch.to_string()
        };
        for c in escaped.chars() {
            if count == limit {
                out.pop();
                out.push('…');
                return out;
            }
            out.push(c);
            count += 1;
        }
    }
    out
}

/// Attach partial command output without changing the error category. A cancel
/// remains exactly Cancelled; its diagnostic is available in debug logging.
fn with_diagnostic(error: BringUpError, diagnostic: &str) -> BringUpError {
    if diagnostic.is_empty() {
        return error;
    }
    let append = |message: String| format!("{message}; {diagnostic}");
    match error {
        BringUpError::EnsureFailed(message) => BringUpError::EnsureFailed(append(message)),
        BringUpError::Ssh(ssh::SshError::Connect(message)) => {
            BringUpError::Ssh(ssh::SshError::Connect(append(message)))
        }
        BringUpError::Ssh(ssh::SshError::Protocol(message)) => {
            BringUpError::Ssh(ssh::SshError::Protocol(append(message)))
        }
        other => other,
    }
}

/// Runs `script` under `sh` on stream `stream`. `what` names it in errors.
pub(crate) fn run(
    sub: &mut dyn ChannelSubstrate,
    events: &Events,
    stream: u8,
    what: &str,
    script: &str,
    deadline: Duration,
    cancel: &knock::Cancel,
) -> Result<Output, BringUpError> {
    let result = run_until_exit(sub, events, stream, what, script, deadline, cancel);
    let mut output = events.take_output(stream);
    let diagnostic = output.diagnostic();
    // Successful machine stdout may contain identity records: log only stderr.
    // On failure, include the bounded partial response, outside the collector lock.
    let logged = output.diagnostic_streams(!matches!(result, Ok(0)));
    if !logged.is_empty() {
        log::debug!(target: "bringup", "{what}: {}; {logged}", match &result {
            Ok(code) => format!("exit {code}"),
            Err(error) => escaped(&error.to_string(), MAX_DIAGNOSTIC),
        });
    }
    output.code = result.map_err(|error| with_diagnostic(error, &diagnostic))?;
    if let Some(data_type) = output.unsupported_type {
        return Err(with_diagnostic(
            BringUpError::EnsureFailed(format!(
                "{what} returned unsupported SSH extended data type {data_type}"
            )),
            &diagnostic,
        ));
    }
    Ok(output)
}

fn run_until_exit(
    sub: &mut dyn ChannelSubstrate,
    events: &Events,
    stream: u8,
    what: &str,
    script: &str,
    deadline: Duration,
    cancel: &knock::Cancel,
) -> Result<i32, BringUpError> {
    if cancel.is_cancelled() {
        return Err(BringUpError::Ssh(ssh::SshError::Cancelled));
    }
    events.prepare(stream);
    sub.open(&OpenRequest {
        stream,
        kind: ChannelKind::Command,
        cols: 0,
        rows: 0,
        screen: false,
        command: shell::posix(script).into_bytes(),
    });
    let started = Instant::now();
    loop {
        if cancel.is_cancelled() {
            sub.close(stream);
            return Err(BringUpError::Ssh(ssh::SshError::Cancelled));
        }
        let event =
            events.recv_timeout(knock::SLICE.min(deadline.saturating_sub(started.elapsed())));
        if cancel.is_cancelled() {
            sub.close(stream);
            return Err(BringUpError::Ssh(ssh::SshError::Cancelled));
        }
        match event {
            Ok(Event::Channel(SubstrateEvent::Exit { ch, code })) if ch == stream => {
                if code == -1 {
                    match closed_within(
                        events,
                        CLOSED_GRACE.min(deadline.saturating_sub(started.elapsed())),
                        cancel,
                    ) {
                        Ok(Some(reason)) => return Err(lost(what, &reason)),
                        Ok(None) => {}
                        Err(error) => {
                            sub.close(stream);
                            return Err(error);
                        }
                    }
                }
                return Ok(code);
            }
            Ok(Event::Channel(SubstrateEvent::Refused { ch, reason })) if ch == stream => {
                return Err(BringUpError::EnsureFailed(format!(
                    "the server would not run {what}: {}",
                    escaped(&reason, MAX_DIAGNOSTIC)
                )));
            }
            Ok(Event::Closed(reason)) => return Err(lost(what, &reason)),
            Ok(_) | Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                return Err(BringUpError::Ssh(ssh::SshError::Protocol(
                    "the connection stopped reporting".into(),
                )));
            }
        }
        if started.elapsed() > deadline {
            sub.close(stream);
            return Err(BringUpError::EnsureFailed(format!(
                "{what} did not finish within {} s",
                deadline.as_secs()
            )));
        }
    }
}

fn lost(what: &str, reason: &str) -> BringUpError {
    BringUpError::Ssh(ssh::SshError::Connect(format!(
        "the connection closed while running {what}: {}",
        escaped(reason, MAX_DIAGNOSTIC)
    )))
}

/// After an `Exit` without a status, wait briefly for `Closed` or cancel.
fn closed_within(
    events: &Events,
    grace: Duration,
    cancel: &knock::Cancel,
) -> Result<Option<String>, BringUpError> {
    let until = Instant::now() + grace;
    while Instant::now() < until {
        if cancel.is_cancelled() {
            return Err(BringUpError::Ssh(ssh::SshError::Cancelled));
        }
        let event =
            events.recv_timeout(knock::SLICE.min(until.saturating_duration_since(Instant::now())));
        if cancel.is_cancelled() {
            return Err(BringUpError::Ssh(ssh::SshError::Cancelled));
        }
        match event {
            Ok(Event::Closed(reason)) => return Ok(Some(reason)),
            Ok(Event::Channel(_)) | Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Ok(None),
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct Silent;
    impl crate::BringUpObserver for Silent {
        fn on_progress(&self, _: crate::BringUpProgress) {}
    }
    fn collector() -> (Collector, Events) {
        super::collector(Arc::new(Silent))
    }

    /// Records what `run` asks of the connection.
    #[derive(Default)]
    struct FakeSubstrate {
        opened: Arc<Mutex<Vec<u8>>>,
        closed: Arc<Mutex<Vec<u8>>>,
    }

    impl ChannelSubstrate for FakeSubstrate {
        fn open(&mut self, req: &OpenRequest) {
            self.opened.lock().unwrap().push(req.stream);
        }
        fn send(&mut self, _: u8, _: &[u8]) {}
        fn resize(&mut self, _: u8, _: u16, _: u16) {}
        fn close(&mut self, ch: u8) {
            self.closed.lock().unwrap().push(ch);
        }
        fn on_bytes(&mut self, _: u8, _: &[u8]) -> Vec<SubstrateEvent> {
            Vec::new()
        }
    }

    const STREAM: u8 = 2;

    fn data(ch: u8, bytes: &[u8]) -> Event {
        Event::Channel(SubstrateEvent::Data {
            ch,
            bytes: bytes.to_vec(),
        })
    }

    fn exit(ch: u8, code: i32) -> Event {
        Event::Channel(SubstrateEvent::Exit { ch, code })
    }

    /// Runs with `events` already queued; the sender stays alive (returned)
    /// so an empty queue is silence, not a stopped connection.
    fn run_fed(
        sub: &mut FakeSubstrate,
        events: Vec<Event>,
        deadline: Duration,
        cancel: &knock::Cancel,
    ) -> (Result<Output, BringUpError>, Collector) {
        let (tx, rx) = collector();
        for e in events {
            tx.send(e);
        }
        let r = run(sub, &rx, STREAM, "the thing", "true", deadline, cancel);
        (r, tx)
    }

    fn fed(events: Vec<Event>) -> Result<Output, BringUpError> {
        let mut sub = FakeSubstrate::default();
        run_fed(
            &mut sub,
            events,
            Duration::from_secs(10),
            &knock::Cancel::new(),
        )
        .0
    }

    fn extended(ch: u8, data_type: u32, bytes: &[u8]) -> Event {
        Event::Channel(SubstrateEvent::ExtendedData {
            ch,
            data_type,
            bytes: bytes.to_vec(),
        })
    }

    #[test]
    fn streams_join_fragments_before_utf8_decoding() {
        let out = fed(vec![
            data(STREAM, b"a\xe2"),
            extended(STREAM, 1, b"warn\xc3"),
            data(STREAM, b"\x82\xac"),
            extended(STREAM, 1, b"\xa9"),
            exit(STREAM, 0),
        ])
        .unwrap();
        assert_eq!(out.complete_stdout().unwrap(), "a€");
        assert_eq!(out.stderr, "warné".as_bytes());
    }

    #[test]
    fn stderr_flood_does_not_consume_stdout_or_exit_capacity() {
        let mut events = (0..1024)
            .map(|_| extended(STREAM, 1, &[b'w'; 4096]))
            .collect::<Vec<_>>();
        events.extend([data(STREAM, b"answer"), exit(STREAM, 7)]);
        let out = fed(events).unwrap();
        assert_eq!(out.code, 7);
        assert_eq!(out.complete_stdout().unwrap(), "answer");
        assert_eq!(out.stderr.len(), MAX_STDERR);
        assert!(out.stderr_truncated);
        assert!(out.diagnostic().contains("stderr (truncated)"));
    }

    #[test]
    fn stdout_at_limit_is_complete_but_an_extra_byte_is_not() {
        let full = vec![b'x'; MAX_OUTPUT];
        let out = fed(vec![
            data(STREAM, &full),
            data(STREAM, b""),
            exit(STREAM, 0),
        ])
        .unwrap();
        assert_eq!(out.complete_stdout().unwrap().len(), MAX_OUTPUT);
        let out = fed(vec![
            data(STREAM, &full),
            data(STREAM, b"!"),
            exit(STREAM, 0),
        ])
        .unwrap();
        assert!(out.complete_stdout().unwrap_err().contains("truncated"));
        let out = fed(vec![data(STREAM, b"\xff"), exit(STREAM, 0)]).unwrap();
        assert!(out.complete_stdout().unwrap_err().contains("UTF-8"));
    }

    #[test]
    fn prepare_preserves_truncation_but_not_foreign_errors() {
        let out = fed(vec![
            data(1, &vec![b'x'; MAX_OUTPUT]),
            data(STREAM, b"answer"),
            exit(STREAM, 0),
        ])
        .unwrap();
        assert!(
            out.complete_stdout().is_err(),
            "discarded prefix must not become trusted"
        );
        let out = fed(vec![
            extended(1, 99, b"unknown"),
            extended(1, 1, &vec![b'x'; MAX_STDERR + 1]),
            data(STREAM, b"answer"),
            exit(STREAM, 0),
        ])
        .unwrap();
        assert_eq!(out.complete_stdout().unwrap(), "answer");
        assert!(!out.stderr_truncated);
    }

    #[test]
    fn unknown_extensions_are_bounded_and_never_become_stdout() {
        let (tx, rx) = collector();
        for _ in 0..1024 {
            tx.send(extended(STREAM, 99, b"unrecognized"));
        }
        assert!(rx.0.buffered.lock().unwrap().terminal.is_empty());
        tx.send(exit(STREAM, 0));
        let error = run(
            &mut FakeSubstrate::default(),
            &rx,
            STREAM,
            "test",
            "true",
            Duration::from_secs(1),
            &knock::Cancel::new(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("extended data type 99"));
    }

    #[test]
    fn diagnostics_escape_controls_prioritize_stderr_and_bound_combined_excerpt() {
        let out = fed(vec![
            data(STREAM, &vec![b'o'; MAX_OUTPUT]),
            extended(STREAM, 1, b"\x1b[31mdenied\n\r\t\x07"),
            exit(STREAM, 1),
        ])
        .unwrap();
        let diagnostic = out.diagnostic();
        assert!(diagnostic.starts_with("stderr:"));
        assert!(diagnostic.contains("denied"));
        assert!(!diagnostic.chars().any(char::is_control));
        assert!(diagnostic.chars().count() <= 1000);
    }

    #[test]
    fn prepare_releases_foreign_payload_budget_and_rejects_late_foreign_data() {
        let (tx, rx) = collector();
        for ch in 0..=u8::MAX {
            tx.send(data(ch, &[b'o'; 1024]));
            tx.send(extended(ch, 1, &[b'e'; 1024]));
        }
        {
            let state = rx.0.buffered.lock().unwrap();
            assert_eq!(state.output_len, MAX_OUTPUT);
            assert_eq!(state.stderr_len, MAX_STDERR);
            assert!(state.terminal.is_empty());
        }
        rx.prepare(STREAM);
        tx.send(data(1, b"late"));
        tx.send(extended(1, 1, b"late"));
        tx.send(extended(1, 99, b"late"));
        let state = rx.0.buffered.lock().unwrap();
        assert_eq!(state.output.len(), 1);
        assert_eq!(state.output_len, 1024);
        assert_eq!(state.stderr_len, 1024);
        assert!(state.output[&STREAM].unsupported_type.is_none());
    }

    #[test]
    fn partial_stderr_survives_timeout_and_connection_failure() {
        for closed in [false, true] {
            let mut events = vec![data(STREAM, b"partial"), extended(STREAM, 1, b"reason")];
            if closed {
                events.push(Event::Closed("disconnected".into()));
            }
            let (result, _tx) = run_fed(
                &mut FakeSubstrate::default(),
                events,
                Duration::from_millis(10),
                &knock::Cancel::new(),
            );
            let error = result.unwrap_err();
            assert!(error.to_string().contains("stderr: reason"));
            assert!(error.to_string().contains("stdout: partial"));
            assert_eq!(
                matches!(error, BringUpError::Ssh(ssh::SshError::Connect(_))),
                closed
            );
        }
    }

    #[test]
    fn exec_flood_keeps_exit_and_cancel() {
        use ssh::SshEvents;
        let (tx, rx) = collector();
        let collector = tx;
        for _ in 0..1024 {
            collector.on_channel(SubstrateEvent::Data {
                ch: STREAM,
                bytes: vec![b'a'; 4096],
            });
        }
        collector.on_channel(SubstrateEvent::Exit {
            ch: STREAM,
            code: 9,
        });
        assert_eq!(rx.0.buffered.lock().unwrap().output_len, 64 * 1024);
        let mut sub = FakeSubstrate::default();
        let out = run(
            &mut sub,
            &rx,
            STREAM,
            "flood",
            "true",
            Duration::from_secs(1),
            &knock::Cancel::new(),
        )
        .unwrap();
        let captured_output = out.stdout;
        assert_eq!(captured_output.len(), 64 * 1024);
        assert_eq!(out.code, 9);

        let cancel = knock::Cancel::new();
        let mut sub = FakeSubstrate::default();
        let opened = Arc::clone(&sub.opened);
        let started = Instant::now();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                while opened.lock().unwrap().is_empty() {
                    std::thread::yield_now();
                }
                for _ in 0..1024 {
                    collector.on_channel(SubstrateEvent::Data {
                        ch: STREAM,
                        bytes: vec![b'b'; 4096],
                    });
                    collector.on_channel(SubstrateEvent::ExtendedData {
                        ch: STREAM,
                        data_type: 1,
                        bytes: vec![b'w'; 4096],
                    });
                }
                cancel.cancel();
            });
            let result = run(
                &mut sub,
                &rx,
                STREAM,
                "flood",
                "true",
                Duration::from_secs(2),
                &cancel,
            );
            assert!(matches!(
                result,
                Err(BringUpError::Ssh(ssh::SshError::Cancelled))
            ));
        });
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(*sub.closed.lock().unwrap(), vec![STREAM]);
    }

    #[test]
    fn cancel_while_waiting_for_closed_closes_the_channel() {
        let (tx, events) = collector();
        tx.send(exit(STREAM, -1));
        let cancel = knock::Cancel::new();
        let mut sub = FakeSubstrate::default();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                while !events.0.buffered.lock().unwrap().terminal.is_empty() {
                    std::thread::yield_now();
                }
                std::thread::sleep(knock::SLICE);
                cancel.cancel();
            });
            let result = run(
                &mut sub,
                &events,
                STREAM,
                "the thing",
                "true",
                Duration::from_secs(2),
                &cancel,
            );
            assert!(matches!(
                result,
                Err(BringUpError::Ssh(ssh::SshError::Cancelled))
            ));
        });
        assert_eq!(*sub.closed.lock().unwrap(), vec![STREAM]);
    }

    #[test]
    fn closed_wins_over_a_flood_and_a_successful_exit() {
        let result = fed(vec![
            data(STREAM, &vec![b'a'; 1024 * 1024]),
            exit(STREAM, 0),
            Event::Closed("lost".into()),
        ]);
        assert!(matches!(
            result,
            Err(BringUpError::Ssh(ssh::SshError::Connect(_)))
        ));
    }

    #[test]
    fn a_normal_exit_gives_the_code_and_the_output() {
        let mut sub = FakeSubstrate::default();
        let (r, _tx) = run_fed(
            &mut sub,
            vec![data(STREAM, b"hel"), data(STREAM, b"lo"), exit(STREAM, 3)],
            Duration::from_secs(10),
            &knock::Cancel::new(),
        );
        let out = r.unwrap();
        assert_eq!((out.code, out.complete_stdout().unwrap()), (3, "hello"));
        assert_eq!(*sub.opened.lock().unwrap(), vec![STREAM]);
        assert!(sub.closed.lock().unwrap().is_empty());
    }

    #[test]
    fn other_streams_events_are_ignored() {
        let out = fed(vec![
            data(1, b"not mine"),
            exit(1, -1),
            Event::Channel(SubstrateEvent::Refused {
                ch: 1,
                reason: "no".into(),
            }),
            data(STREAM, b"mine"),
            exit(STREAM, 0),
        ])
        .unwrap();
        assert_eq!((out.code, out.complete_stdout().unwrap()), (0, "mine"));
    }

    #[test]
    fn an_exit_without_status_then_closed_is_a_lost_connection() {
        match fed(vec![
            data(STREAM, b"partial"),
            exit(STREAM, -1),
            Event::Closed("the connection was lost".into()),
        ]) {
            Err(BringUpError::Ssh(ssh::SshError::Connect(m))) => assert_eq!(
                m,
                "the connection closed while running the thing: the connection was lost; stdout: partial"
            ),
            other => panic!("expected a lost connection, got {other:?}"),
        }
    }

    #[test]
    fn an_exit_without_status_and_no_closed_is_code_minus_one() {
        let started = Instant::now();
        let out = fed(vec![data(STREAM, b"x"), exit(STREAM, -1)]).unwrap();
        assert_eq!((out.code, out.complete_stdout().unwrap()), (-1, "x"));
        assert!(started.elapsed() >= CLOSED_GRACE, "{:?}", started.elapsed());
    }

    #[test]
    fn a_refused_channel_names_the_command() {
        match fed(vec![Event::Channel(SubstrateEvent::Refused {
            ch: STREAM,
            reason: "administratively prohibited".into(),
        })]) {
            Err(BringUpError::EnsureFailed(m)) => assert_eq!(
                m,
                "the server would not run the thing: administratively prohibited"
            ),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn the_deadline_closes_the_channel() {
        let mut sub = FakeSubstrate::default();
        let (r, _tx) = run_fed(
            &mut sub,
            vec![data(STREAM, b"still going")],
            Duration::from_millis(200),
            &knock::Cancel::new(),
        );
        match r {
            Err(BringUpError::EnsureFailed(m)) => {
                assert_eq!(
                    m,
                    "the thing did not finish within 0 s; stdout: still going"
                )
            }
            other => panic!("expected the deadline, got {other:?}"),
        }
        assert_eq!(*sub.closed.lock().unwrap(), vec![STREAM]);
    }

    #[test]
    fn an_already_cancelled_command_is_never_opened() {
        let mut sub = FakeSubstrate::default();
        let cancel = knock::Cancel::new();
        cancel.cancel();
        let (r, _tx) = run_fed(&mut sub, vec![], Duration::from_secs(10), &cancel);
        assert!(
            matches!(r, Err(BringUpError::Ssh(ssh::SshError::Cancelled))),
            "{r:?}"
        );
        assert!(sub.opened.lock().unwrap().is_empty());
        assert!(sub.closed.lock().unwrap().is_empty());
    }

    #[test]
    fn missing_exit_status_does_not_extend_the_command_budget() {
        let started = Instant::now();
        let mut sub = FakeSubstrate::default();
        let (output, _tx) = run_fed(
            &mut sub,
            vec![exit(STREAM, -1)],
            Duration::from_millis(30),
            &knock::Cancel::new(),
        );
        assert_eq!(output.unwrap().code, -1);
        assert!(started.elapsed() < Duration::from_millis(250));
    }

    #[test]
    fn output_past_the_cap_is_dropped_but_read_until_exit() {
        let chunk = vec![b'a'; 40 * 1024];
        let out = fed(vec![
            data(STREAM, &chunk),
            data(STREAM, &chunk),
            data(STREAM, &chunk),
            data(STREAM, b"tail"),
            exit(STREAM, 0),
        ])
        .unwrap();
        assert_eq!(out.code, 0);
        assert_eq!(out.stdout.len(), MAX_OUTPUT);
        assert!(out.stdout.iter().all(|b| *b == b'a'));
    }
}
