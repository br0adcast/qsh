//! Owned Linux self-check execution: result and cleanup are separate receipts.

use super::{spawn_self_check, SelfCheck};
use nix::libc;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::process::ChildStdout;
use std::time::{Duration, Instant};
use transport::channel_server::{ChannelWait, ChildStatus, LeaderStatus};

const LINE_LIMIT: usize = 4096;
const OBSERVE_INTERVAL: Duration = Duration::from_millis(20);

fn nonblocking(pipe: &ChildStdout) -> std::io::Result<()> {
    fn retry(mut operation: impl FnMut() -> i32) -> std::io::Result<i32> {
        loop {
            let result = operation();
            if result >= 0 {
                return Ok(result);
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
    let flags = retry(|| unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_GETFL) })?;
    retry(|| unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) })?;
    Ok(())
}

// One bounded read per progress step. Closing the first-line reader preserves
// the previous reader's behavior without creating an unjoined worker.
fn read_line_step<R: Read>(
    pipe: &mut Option<R>,
    bytes: &mut Vec<u8>,
) -> Option<Result<String, String>> {
    let reader = pipe.as_mut()?;
    let mut buffer = [0; LINE_LIMIT];
    let amount = match reader.read(&mut buffer[..LINE_LIMIT - bytes.len()]) {
        Ok(amount) => amount,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) =>
        {
            return None
        }
        Err(error) => {
            pipe.take();
            return Some(Err(format!("self-check output could not be read: {error}")));
        }
    };
    let end = buffer[..amount].iter().position(|&byte| byte == b'\n');
    bytes.extend_from_slice(&buffer[..end.map_or(amount, |index| index + 1)]);
    if amount != 0 && end.is_none() && bytes.len() < LINE_LIMIT {
        return None;
    }
    pipe.take();
    Some(
        String::from_utf8(std::mem::take(bytes))
            .map_err(|_| "self-check output is not UTF-8".into()),
    )
}

pub(super) fn run(path: &Path, timeout: Duration) -> Result<SelfCheck, String> {
    let view = crate::process_scope::prepare()?;
    let mut child = spawn_self_check(path)?;
    let mut pipe = child.stdout.take();
    // Spawn completed its setsid/exec handshake. Custody precedes every
    // fallible descriptor operation, including configuring nonblocking I/O.
    let wait = crate::process_scope::own_child(Box::new(child), view);
    let pipe = match pipe.take() {
        Some(pipe) => nonblocking(&pipe)
            .map(|()| pipe)
            .map_err(|error| format!("self-check output could not be prepared: {error}")),
        None => Err("self-check output is unavailable".into()),
    };
    run_owned(wait, pipe, timeout)
}

fn run_owned<R: Read>(
    mut wait: Box<dyn ChannelWait>,
    pipe: Result<R, String>,
    timeout: Duration,
) -> Result<SelfCheck, String> {
    let deadline = Instant::now() + timeout;
    let (mut pipe, mut result) = match pipe {
        Ok(pipe) => (Some(pipe), None),
        Err(error) => (None, Some(Err(error))),
    };
    let mut line = None;
    let mut bytes = Vec::with_capacity(LINE_LIMIT);
    let mut leader = None;
    let mut stopping = false;
    loop {
        if result.is_none() {
            // The deadline concerns unfinished verification work only. Once
            // result is latched, mandatory cleanup grace cannot change it.
            if Instant::now() >= deadline {
                result = Some(Err(format!(
                    "self-check did not complete within {}ms",
                    timeout.as_millis()
                )));
            } else {
                if line.is_none() {
                    line = read_line_step(&mut pipe, &mut bytes);
                }
                match wait.poll_leader_status() {
                    Some(LeaderStatus::Exited { code }) => leader = Some(code),
                    Some(LeaderStatus::Unknown(error)) => result = Some(Err(error)),
                    Some(LeaderStatus::Running) | None => {}
                }
                if result.is_none() {
                    match leader {
                        Some(Some(0)) => {
                            if let Some(output) = line.take() {
                                result = Some(output.and_then(|output| {
                                    SelfCheck::from_line(output.lines().next().unwrap_or(""))
                                        .map_err(|error| {
                                            format!("self-check printed something else: {error:#}")
                                        })
                                }));
                            }
                        }
                        Some(Some(code)) => {
                            result = Some(Err(format!("self-check failed with exit code {code}")))
                        }
                        Some(None) => {
                            result = Some(Err("self-check exit status is unavailable".into()))
                        }
                        None => {
                            if matches!(line, Some(Err(_))) {
                                if let Some(Err(error)) = line.take() {
                                    result = Some(Err(error));
                                }
                            }
                        }
                    }
                }
            }
        }
        if matches!(result, Some(Err(_))) && !stopping {
            pipe.take();
            wait.kill();
            stopping = true;
        }
        match wait.poll_exit() {
            ChildStatus::Reaped { .. } => {
                if let Some(result) = result {
                    return result;
                }
            }
            // Unknown retains this actual callback, its scope and the caller's
            // executing permit. Neither timeout nor dropping a handle is proof.
            ChildStatus::Running | ChildStatus::WaitingForWorkers | ChildStatus::Unknown(_) => {}
        }
        std::thread::sleep(OBSERVE_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Error, ErrorKind};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    };

    struct Wait {
        code: Option<i32>,
        killed: Arc<AtomicBool>,
        held: Option<Arc<AtomicBool>>,
        observed: Option<mpsc::Sender<()>>,
    }
    impl ChannelWait for Wait {
        fn cleanup_uninstalled(
            &mut self,
            _: &transport::channel_open::CleanupAuthority<'_>,
        ) -> transport::channel_open::CleanupStatus {
            panic!("the verification callback owns progress directly")
        }
        fn poll_leader_status(&mut self) -> Option<LeaderStatus> {
            Some(match self.code {
                Some(code) => LeaderStatus::Exited { code: Some(code) },
                None => LeaderStatus::Running,
            })
        }
        fn poll_exit(&mut self) -> ChildStatus {
            if let Some(tx) = self.observed.take() {
                tx.send(()).unwrap();
            }
            let complete = self.held.as_ref().map_or_else(
                || self.killed.load(Ordering::Acquire),
                |release| release.load(Ordering::Acquire),
            );
            if complete {
                ChildStatus::Reaped {
                    code: Some(self.code.unwrap_or(0)),
                }
            } else {
                ChildStatus::Unknown("controlled pending receipt".into())
            }
        }
        fn kill(&mut self) {
            self.killed.store(true, Ordering::Release);
        }
        fn wait(self: Box<Self>) -> i32 {
            panic!("must use actual progress receipts")
        }
    }
    struct Denied;
    impl Read for Denied {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(Error::new(
                ErrorKind::PermissionDenied,
                "injected read denial",
            ))
        }
    }
    #[test]
    fn verification39_read_failure_requests_cleanup_before_deadline() {
        let killed = Arc::new(AtomicBool::new(false));
        let result = run_owned(
            Box::new(Wait {
                code: None,
                killed: killed.clone(),
                held: None,
                observed: None,
            }),
            Ok(Denied),
            Duration::from_millis(80),
        );
        assert!(killed.load(Ordering::Acquire));
        assert!(
            result.unwrap_err().contains("could not be read"),
            "read failure must not be replaced by a later timeout"
        );
    }
    #[test]
    fn verification39_setup_error_retains_callback_through_unknown_cleanup() {
        let release = Arc::new(AtomicBool::new(false));
        let killed = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        let wait = Wait {
            code: None,
            killed: killed.clone(),
            held: Some(release.clone()),
            observed: Some(tx),
        };
        let done = finished.clone();
        let worker = std::thread::spawn(move || {
            let result = run_owned::<Cursor<Vec<u8>>>(
                Box::new(wait),
                Err("injected setup failure".into()),
                Duration::from_millis(1),
            );
            done.store(true, Ordering::Release);
            result
        });
        rx.recv_timeout(Duration::from_secs(2)).unwrap();
        std::thread::sleep(Duration::from_millis(30));
        let returned_before_receipt = finished.load(Ordering::Acquire);
        let stop_requested = killed.load(Ordering::Acquire);
        release.store(true, Ordering::Release);
        let result = worker.join().unwrap(); // Actual owner joined before assertions.
        assert!(
            !returned_before_receipt,
            "Unknown cleanup released callback ownership"
        );
        assert!(stop_requested);
        assert_eq!(result.unwrap_err(), "injected setup failure");
    }
    fn valid_line() -> Vec<u8> {
        br#"{"build":101,"arch":"fixture","protocol":1,"protocols":[1],"handover_versions":[1]}"#
            .to_vec()
    }
    fn completed_wait(code: i32) -> Box<dyn ChannelWait> {
        Box::new(Wait {
            code: Some(code),
            killed: Arc::new(AtomicBool::new(false)),
            held: Some(Arc::new(AtomicBool::new(true))),
            observed: None,
        })
    }
    #[test]
    fn verification39_eof_utf8_and_line_limit_remain_bounded() {
        let result = run_owned(
            completed_wait(0),
            Ok(Cursor::new(valid_line())),
            Duration::from_secs(1),
        );
        assert_eq!(
            result.unwrap().build,
            101,
            "EOF can complete the bounded first line"
        );
        for bytes in [vec![0xff, b'\n'], Vec::new(), vec![b'x'; LINE_LIMIT * 8]] {
            assert!(run_owned(
                completed_wait(0),
                Ok(Cursor::new(bytes)),
                Duration::from_secs(1)
            )
            .is_err());
        }
        let mut reader = Some(Cursor::new(vec![b'x'; LINE_LIMIT * 8]));
        let mut collected = Vec::new();
        assert_eq!(
            read_line_step(&mut reader, &mut collected)
                .unwrap()
                .unwrap()
                .len(),
            LINE_LIMIT
        );
        assert!(
            reader.is_none(),
            "first-line budget must close the owned reader"
        );
    }
    #[test]
    fn verification39_valid_line_cannot_override_failed_leader() {
        let result = run_owned(
            completed_wait(7),
            Ok(Cursor::new(valid_line())),
            Duration::from_secs(1),
        );
        assert!(result.unwrap_err().contains("exit code 7"));
    }
    #[test]
    fn verification39_valid_line_cannot_override_unfinished_work_deadline() {
        let killed = Arc::new(AtomicBool::new(false));
        let wait = Wait {
            code: None,
            killed: killed.clone(),
            held: None,
            observed: None,
        };
        let result = run_owned(
            Box::new(wait),
            Ok(Cursor::new(valid_line())),
            Duration::from_millis(40),
        );
        assert!(killed.load(Ordering::Acquire));
        assert!(result.unwrap_err().contains("did not complete"));
    }
}
