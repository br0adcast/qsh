//! Questions to a person, asked on the controlling terminal.
//!
//! Every question opens `/dev/tty` itself rather than using stdin/stdout,
//! which may be busy or redirected. Without a terminal the answer is "no":
//! a script gets a refusal, not a hang.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use crate::report::printable;
use crate::tty::EchoOff;

/// How many times an unclear yes/no answer is asked again.
const CONFIRM_RETRIES: usize = 3;

#[derive(Clone)]
pub struct Tty {
    path: PathBuf,
}

impl Default for Tty {
    fn default() -> Self {
        Tty::new()
    }
}

impl Tty {
    pub fn new() -> Tty {
        Tty::at("/dev/tty")
    }

    /// A terminal at another path; for tests.
    pub fn at(path: impl Into<PathBuf>) -> Tty {
        Tty { path: path.into() }
    }

    fn open(&self) -> Option<File> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.path)
            .ok()
    }

    /// A line to the terminal (not stderr).
    pub fn say(&self, text: &str) {
        if let Some(mut f) = self.open() {
            let _ = writeln!(f, "{text}");
        }
    }

    /// Asks yes/no; no terminal, or no clear answer, is `false`.
    pub fn confirm(&self, question: &str) -> bool {
        self.confirm_cancellable(question, &knock::Cancel::new())
            .unwrap_or(false)
    }

    /// Asks on the controlling terminal while polling cancellation, before raw mode.
    pub fn confirm_cancellable(
        &self,
        question: &str,
        cancel: &knock::Cancel,
    ) -> Result<bool, ssh::SshError> {
        self.confirm_with_default(question, cancel, false)
    }

    /// Session replacement defaults to Yes on Enter; EOF and no terminal refuse.
    pub fn confirm_replacement(
        &self,
        question: &str,
        cancel: &knock::Cancel,
    ) -> Result<bool, ssh::SshError> {
        self.confirm_with_default(question, cancel, true)
    }

    /// Installation defaults to yes on Enter; EOF still refuses.
    pub fn confirm_install(
        &self,
        question: &str,
        cancel: &knock::Cancel,
    ) -> Result<bool, ssh::SshError> {
        self.confirm_with_default(question, cancel, true)
    }

    fn confirm_with_default(
        &self,
        question: &str,
        cancel: &knock::Cancel,
        accept_empty: bool,
    ) -> Result<bool, ssh::SshError> {
        if cancel.is_cancelled() || crate::signals::termination_requested() {
            return Err(ssh::SshError::Cancelled);
        }
        let Some(mut terminal) = self.open() else {
            return Ok(false);
        };
        let suffix = if accept_empty { "[Y/n]" } else { "[y/N]" };
        let _ = write!(terminal, "{question} {suffix} ");
        let _ = terminal.flush();
        let mut answer = Vec::new();
        for attempt in 0..=CONFIRM_RETRIES {
            answer.clear();
            loop {
                if cancel.is_cancelled() || crate::signals::termination_requested() {
                    return Err(ssh::SshError::Cancelled);
                }
                let mut fd = libc::pollfd {
                    fd: terminal.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: fd is live and points to one pollfd throughout the call.
                let ready = unsafe { libc::poll(&mut fd, 1, 50) };
                if ready < 0 {
                    if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Ok(false);
                }
                if ready == 0 {
                    continue;
                }
                let mut byte = [0];
                match terminal.read(&mut byte) {
                    Ok(0) => return Ok(false),
                    Ok(_) if byte[0] == b'\n' => break,
                    Ok(_) if answer.len() < 128 => answer.push(byte[0]),
                    Ok(_) => return Ok(false),
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => return Ok(false),
                }
            }
            match String::from_utf8_lossy(&answer)
                .trim()
                .to_ascii_lowercase()
                .as_str()
            {
                "" => return Ok(accept_empty),
                "yes" | "y" => return Ok(true),
                "no" | "n" => return Ok(false),
                _ => {}
            }
            if attempt < CONFIRM_RETRIES {
                let _ = write!(terminal, "Please type 'yes' or 'no': ");
                let _ = terminal.flush();
            }
        }
        Ok(false)
    }

    /// Reads a secret with echo off; an empty answer is `None`, and so is a
    /// terminal whose echo would not go off: a secret is never read on
    /// screen.
    pub fn secret(&self, prompt: &str) -> Option<ssh::Zeroizing<String>> {
        let mut out = self.open()?;
        let input = out.try_clone().ok()?;
        let _ = write!(out, "{prompt}");
        let _ = out.flush();
        let mut line = ssh::Zeroizing::new(String::new());
        let read = {
            // Echo comes back when the guard drops, before the newline; a
            // signal meanwhile puts it back too (see `EchoOff`).
            let Ok(_quiet) = EchoOff::enter(input.as_raw_fd()) else {
                let _ = writeln!(out);
                return None;
            };
            BufReader::new(input).read_line(&mut line)
        };
        let _ = writeln!(out);
        match read {
            Ok(n) if n > 0 => {}
            _ => return None,
        }
        let trimmed = line.trim_end_matches(['\n', '\r']);
        if trimmed.is_empty() {
            return None;
        }
        Some(ssh::Zeroizing::new(trimmed.to_string()))
    }

    /// Reads one visible line.
    pub fn line(&self, prompt: &str) -> Option<String> {
        let mut out = self.open()?;
        let _ = write!(out, "{prompt}");
        let _ = out.flush();
        let mut line = Vec::new();
        loop {
            if crate::signals::termination_requested() {
                return None;
            }
            let mut fd = libc::pollfd {
                fd: out.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: out owns the live descriptor and fd points to one pollfd.
            let ready = unsafe { libc::poll(&mut fd, 1, 50) };
            if ready < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return None;
            }
            if ready == 0 {
                continue;
            }
            let mut byte = [0];
            match out.read(&mut byte) {
                Ok(0) => return None,
                Ok(_) if byte[0] == b'\n' => {
                    return String::from_utf8(line)
                        .ok()
                        .map(|text| text.trim_end_matches('\r').to_owned())
                }
                Ok(_) => line.push(byte[0]),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return None,
            }
        }
    }
}

impl crate::trust::Confirm for Tty {
    fn ask(&self, prompt: &str) -> bool {
        self.confirm(prompt)
    }
}

impl crate::keys::Passphrase for Tty {
    fn ask(&self, prompt: &str) -> Option<String> {
        self.secret(prompt).map(|s| s.to_string())
    }
}

/// Answers the ssh login's questions on the terminal.
pub struct SshPrompter(pub Tty);

impl ssh::AuthPrompter for SshPrompter {
    fn passphrase(&self, key_path: &Path) -> Option<ssh::Zeroizing<String>> {
        self.0.secret(&format!(
            "Enter passphrase for key '{}': ",
            key_path.display()
        ))
    }

    fn password(&self, user: &str, host: &str) -> Option<ssh::Zeroizing<String>> {
        self.0.secret(&format!("{user}@{host}'s password: "))
    }

    fn keyboard_interactive(
        &self,
        name: &str,
        instructions: &str,
        prompts: &[ssh::Prompt],
    ) -> Option<Vec<ssh::Zeroizing<String>>> {
        // All three texts are the server's: see `report::printable`.
        if !name.is_empty() {
            self.0.say(&printable(name));
        }
        if !instructions.is_empty() {
            self.0.say(&printable(instructions));
        }
        let mut answers = Vec::with_capacity(prompts.len());
        for p in prompts {
            let text = printable(&p.text);
            let answer = if p.echo {
                ssh::Zeroizing::new(self.0.line(&text)?)
            } else {
                self.0.secret(&text)?
            };
            answers.push(answer);
        }
        Some(answers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn installation_default_does_not_change_trust_confirmation() {
        let _serialize = crate::tty::SIGNAL_TESTS
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        for (input, install, expected) in [
            (&b"\n"[..], true, true),
            (&b"n\n"[..], true, false),
            (&b"\x04"[..], true, false),
            (&b"\nno\n"[..], false, false),
        ] {
            let pty = nix::pty::openpty(None, None).unwrap();
            let tty = Tty::at(nix::unistd::ttyname(&pty.slave).unwrap());
            let mut master = File::from(pty.master);
            master.write_all(input).unwrap();
            let cancel = knock::Cancel::new();
            let answer = if install {
                tty.confirm_install("Install?", &cancel)
            } else {
                tty.confirm_cancellable("Trust?", &cancel)
            };
            assert_eq!(answer.unwrap(), expected);
        }
        assert!(!Tty::at("/nonexistent/qsh-test-tty")
            .confirm_install("Install?", &knock::Cancel::new())
            .unwrap());
        let cancel = knock::Cancel::new();
        cancel.cancel();
        assert!(matches!(
            Tty::new().confirm_install("Install?", &cancel),
            Err(ssh::SshError::Cancelled)
        ));
    }

    #[test]
    fn replacement_accepts_enter_but_not_eof_or_missing_terminal() {
        let _serialize = crate::tty::SIGNAL_TESTS
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        for (input, expected) in [
            (&b"\n"[..], true),
            (&b"n\n"[..], false),
            (&b"\x04"[..], false),
            (&b"Y\n"[..], true),
        ] {
            let pty = nix::pty::openpty(None, None).unwrap();
            let tty = Tty::at(nix::unistd::ttyname(&pty.slave).unwrap());
            let mut master = File::from(pty.master);
            master.write_all(input).unwrap();
            assert_eq!(
                tty.confirm_replacement("Replace?", &knock::Cancel::new())
                    .unwrap(),
                expected
            );
        }
        assert!(!Tty::at("/nonexistent/qsh-test-tty")
            .confirm_replacement("Replace?", &knock::Cancel::new())
            .unwrap());
    }

    #[test]
    fn cancellable_confirmation_observes_cancel_without_any_input() {
        let _serialize = crate::tty::SIGNAL_TESTS
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let pty = nix::pty::openpty(None, None).unwrap();
        let path = nix::unistd::ttyname(&pty.slave).unwrap();
        let cancel = knock::Cancel::new();
        std::thread::scope(|scope| {
            let cancellation = cancel.clone();
            scope.spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(60));
                cancellation.cancel();
            });
            let start = std::time::Instant::now();
            assert!(matches!(
                Tty::at(path).confirm_cancellable("Install?", &cancel),
                Err(ssh::SshError::Cancelled)
            ));
            assert!(start.elapsed() < std::time::Duration::from_secs(1));
        });
    }

    #[test]
    fn cancellable_confirmation_requires_an_answer_and_terminal() {
        let _serialize = crate::tty::SIGNAL_TESTS
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert!(!Tty::at("/nonexistent/qsh-test-tty")
            .confirm_cancellable("Install?", &knock::Cancel::new())
            .unwrap());
        let pty = nix::pty::openpty(None, None).unwrap();
        let path = nix::unistd::ttyname(&pty.slave).unwrap();
        let mut master = File::from(pty.master);
        master.write_all(b"yes\n").unwrap();
        assert!(Tty::at(path)
            .confirm_cancellable("Install?", &knock::Cancel::new())
            .unwrap());
    }

    #[test]
    fn without_a_terminal_every_question_is_no() {
        // `secret` reaches `EchoOff::enter` below.
        let _serialize = crate::tty::SIGNAL_TESTS
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tty = Tty::at("/nonexistent/qsh-test-tty");
        assert!(!tty.confirm("trust?"));
        assert!(tty.secret("pw: ").is_none());
        assert!(tty.line("code: ").is_none());
        tty.say("nothing happens");
        // Not a terminal: echo cannot go off, so nothing is read.
        let file = tempfile::NamedTempFile::new().expect("temp file");
        std::fs::write(file.path(), "typed\n").expect("write");
        assert!(Tty::at(file.path()).secret("pw: ").is_none());
        let p = SshPrompter(tty);
        use ssh::AuthPrompter as _;
        assert!(p.password("u", "h").is_none());
        assert!(p.passphrase(std::path::Path::new("/k")).is_none());
        assert!(p
            .keyboard_interactive(
                "",
                "",
                &[ssh::Prompt {
                    text: "x".into(),
                    echo: false
                }]
            )
            .is_none());
    }

    /// What the server sends for a keyboard-interactive round is shown with
    /// its control characters defused.
    #[test]
    fn keyboard_interactive_texts_reach_the_terminal_printable() {
        let _serialize = crate::tty::SIGNAL_TESTS
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let pty = nix::pty::openpty(None, None).expect("openpty");
        let path = nix::unistd::ttyname(&pty.slave).expect("the slave's path");
        let mut master = File::from(pty.master);
        master.write_all(b"code\n").expect("type");
        let p = SshPrompter(Tty::at(path));
        use ssh::AuthPrompter as _;
        let answers = p
            .keyboard_interactive(
                "\x1b]0;name\x07",
                "line one\nline \x1b[2Jtwo",
                &[ssh::Prompt {
                    text: "Code\x1b[8m: ".into(),
                    echo: true,
                }],
            )
            .expect("answered");
        assert_eq!(answers[0].as_str(), "code");
        // Everything the prompter wrote, and the echo of what was typed. The
        // pty hands it over in pieces, so read until the last write is in.
        let seen = read_until(&mut master, "Code?[8m: ");
        assert!(!seen.contains('\x1b'), "{seen:?}");
        assert!(seen.contains("?]0;name?"), "{seen:?}");
        assert!(seen.contains("line one line ?[2Jtwo"), "{seen:?}");
        assert!(seen.contains("Code?[8m: "), "{seen:?}");
    }

    #[test]
    fn unicode_controls_in_keyboard_interactive_reach_only_the_display_filter() {
        let _serialize = crate::tty::SIGNAL_TESTS
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let pty = nix::pty::openpty(None, None).unwrap();
        let path = nix::unistd::ttyname(&pty.slave).unwrap();
        let before = nix::sys::termios::tcgetattr(&pty.slave).unwrap();
        let mut master = File::from(pty.master);
        let (done, completed) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            use ssh::AuthPrompter as _;
            let tty = Tty::at(path);
            let answers = SshPrompter(tty.clone()).keyboard_interactive(
                "challenge\u{202e}name",
                "one\u{2028}two\u{2066}three\u{2069}",
                &[
                    ssh::Prompt {
                        text: "code\u{200f} echo-end: ".into(),
                        echo: true,
                    },
                    ssh::Prompt {
                        text: "secret\u{061c}\u{2029} secret-end: ".into(),
                        echo: false,
                    },
                ],
            );
            tty.say("prompt-fixture-done");
            let _ = done.send(());
            answers
        });
        // Match unchanged ASCII suffixes so the original unsafe implementation
        // still completes the interaction before the display assertions fail.
        let mut seen = read_until(&mut master, "echo-end: ");
        let visible_sent = master.write_all("visible-中文\n".as_bytes()).is_ok();
        seen.push_str(&read_until(&mut master, "secret-end: "));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let quiet = loop {
            if nix::sys::termios::tcgetattr(&pty.slave).is_ok_and(|state| {
                !state
                    .local_flags
                    .contains(nix::sys::termios::LocalFlags::ECHO)
            }) {
                break true;
            }
            if std::time::Instant::now() >= deadline {
                break false;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        };
        // Disposable fixture answer, never an account credential. A directional
        // control in the answer must remain byte-exact and must not be echoed.
        let fixture_answer = "fixture-\u{202e}answer";
        let secret_sent = quiet
            && master
                .write_all(format!("{fixture_answer}\n").as_bytes())
                .is_ok();
        let finished = secret_sent
            && completed
                .recv_timeout(std::time::Duration::from_secs(5))
                .is_ok();
        if finished {
            seen.push_str(&read_until(&mut master, "prompt-fixture-done"));
        }
        // Query restoration while the master is still open: after master
        // hangup tcgetattr on its slave can legitimately return EIO.
        let after = nix::sys::termios::tcgetattr(&pty.slave);
        // Closing our only master also releases a blocked slave read on a
        // failure path. Always join the owned reader before any assertion.
        drop(master);
        let answers = worker.join();
        assert!(visible_sent && quiet && secret_sent && finished);
        let answers = answers.unwrap().unwrap();
        assert_eq!(answers[0].as_str(), "visible-中文");
        assert_eq!(answers[1].as_str(), fixture_answer);
        assert!(
            !seen.contains(fixture_answer),
            "the fixture answer was echoed"
        );
        assert!(seen.contains("challenge?name"));
        assert!(seen.contains("one two?three?"));
        assert!(seen.contains("code? echo-end: "));
        assert!(seen.contains("secret?  secret-end: "));
        assert_eq!(after.unwrap().local_flags, before.local_flags);
    }

    /// Reads `master` until `last` has arrived, or 5 s have passed; what was
    /// read either way.
    fn read_until(master: &mut File, last: &str) -> String {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut seen = Vec::new();
        while !String::from_utf8_lossy(&seen).contains(last) {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                break;
            }
            let mut fds = libc::pollfd {
                fd: master.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one valid pollfd for the whole call.
            let ready = unsafe { libc::poll(&mut fds, 1, left.as_millis().min(100) as i32) };
            if ready > 0 {
                let mut buf = [0u8; 4096];
                match master.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => seen.extend_from_slice(&buf[..n]),
                }
            }
        }
        String::from_utf8_lossy(&seen).into_owned()
    }
}
