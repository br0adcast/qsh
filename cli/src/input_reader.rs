//! One owned keyboard reader per interactive shell.

use crate::input_ingress::{IngressBlocked, IngressBudget, READ_BYTES};
use crate::input_wake::{self, WakeReader, WakeSender};
use crate::session::{LocalInputFailure, UiEvent};
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;

struct InputControl {
    cancelled: AtomicBool,
    wake: WakeSender,
}

/// Joining before cooked mode prevents stealing prompt replies or feeding a
/// later session. Drop also joins on early returns and unwinding.
pub struct InputReader {
    control: Arc<InputControl>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl InputReader {
    pub fn start(tx: Sender<UiEvent>) -> io::Result<Self> {
        Self::start_fd(tx, std::io::stdin().as_raw_fd(), IngressBudget::default())
    }

    /// The caller keeps stdin_fd open and exclusively readable until stop/Drop.
    pub fn start_fd(
        tx: Sender<UiEvent>,
        stdin_fd: RawFd,
        budget: IngressBudget,
    ) -> io::Result<Self> {
        let (wake, sender) = input_wake::pair()?;
        let control = Arc::new(InputControl {
            cancelled: AtomicBool::new(false),
            wake: sender,
        });
        let stopped = control.clone();
        let thread = std::thread::Builder::new()
            .name("qsh-input".into())
            .spawn(move || {
                if read_input(&tx, stdin_fd, budget, &stopped, wake).is_err()
                    && !stopped.cancelled.load(Ordering::SeqCst)
                {
                    let _ = tx.send(UiEvent::InputFailure(LocalInputFailure::ReaderUnavailable));
                }
            })?;
        Ok(Self {
            control,
            thread: Some(thread),
        })
    }

    fn stop_inner(&mut self) {
        self.control.cancelled.store(true, Ordering::SeqCst);
        // A hard notification failure closes the owned writer, so HUP also
        // releases the thread. No locks are held across join.
        let _ = self.control.wake.notify();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }

    pub fn stop(mut self) {
        self.stop_inner();
    }
}
impl Drop for InputReader {
    fn drop(&mut self) {
        if self.thread.is_some() {
            self.stop_inner();
        }
    }
}

fn wait_reply(
    reply: &Receiver<bool>,
    control: &InputControl,
    wake: &mut WakeReader,
) -> io::Result<bool> {
    loop {
        if control.cancelled.load(Ordering::SeqCst) {
            return Ok(false);
        }
        match reply.try_recv() {
            Ok(value) => return Ok(value),
            Err(mpsc::TryRecvError::Disconnected) => return Ok(false),
            Err(mpsc::TryRecvError::Empty) => {}
        }
        wake.drain()?;
        // Publication precedes notification. Recheck both authorities after
        // draining and before park, including ack/cancel during drain.
        if control.cancelled.load(Ordering::SeqCst) {
            return Ok(false);
        }
        match reply.try_recv() {
            Ok(value) => return Ok(value),
            Err(mpsc::TryRecvError::Disconnected) => return Ok(false),
            Err(mpsc::TryRecvError::Empty) => {}
        }
        wake.poll_stdin(None)?;
    }
}

fn read_input(
    tx: &Sender<UiEvent>,
    stdin_fd: RawFd,
    budget: IngressBudget,
    control: &InputControl,
    mut wake: WakeReader,
) -> io::Result<()> {
    let mut buf = [0u8; READ_BYTES];
    while !control.cancelled.load(Ordering::SeqCst) {
        wake.drain()?;
        if control.cancelled.load(Ordering::SeqCst) {
            break;
        }
        let readable = wake.poll_stdin(Some(stdin_fd))?;
        if control.cancelled.load(Ordering::SeqCst) {
            break;
        }
        if !readable {
            continue;
        }
        // SAFETY: the caller keeps this descriptor live until join, and buf
        // is writable for its full length. This thread is the sole reader.
        let n = unsafe { libc::read(stdin_fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n == 0 {
            break;
        }
        if n < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        let input = loop {
            if control.cancelled.load(Ordering::SeqCst) {
                return Ok(());
            }
            if let Ok(input) = budget.admit_slice(&buf[..n as usize]) {
                break input;
            }
            let (blocked, reply) =
                IngressBlocked::channel_notified(budget.clone(), n as usize, control.wake.clone());
            if tx.send(UiEvent::IngressBlocked(blocked)).is_err() {
                return Ok(());
            }
            if !wait_reply(&reply, control, &mut wake)? {
                return Ok(());
            }
        };
        if control.cancelled.load(Ordering::SeqCst) {
            break;
        }
        if tx.send(UiEvent::Stdin(input)).is_err() {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::UiEvent;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;
    use std::time::Duration;

    fn stop_bounded(reader: InputReader) {
        stop_bounded_at_poll(reader, None);
    }

    fn stop_bounded_at_poll(reader: InputReader, resume: Option<mpsc::Sender<()>>) {
        let control = reader.control.clone();
        let (done, finished) = mpsc::channel();
        let owner = std::thread::spawn(move || {
            reader.stop();
            let _ = done.send(());
        });
        if let Some(resume) = resume {
            let _ = resume.send(());
        }
        let result = finished.recv_timeout(Duration::from_secs(3));
        // Always release a failed fixture and reap it before asserting.
        control.wake.close_for_test();
        owner.join().unwrap();
        assert!(
            result.is_ok(),
            "reader did not stop without fixture intervention"
        );
    }

    #[test]
    fn input_wake_reader_stops_idle_and_reports_hard_failure() {
        for fail in [false, true] {
            let (read, _write) = UnixStream::pair().unwrap();
            let (tx, rx) = mpsc::channel();
            let reader = InputReader::start_fd(
                tx,
                read.as_raw_fd(),
                crate::input_ingress::IngressBudget::default(),
            )
            .unwrap();
            if fail {
                reader.control.wake.fail_next_notify();
                assert!(reader.control.wake.notify().is_err());
                let result = rx.recv_timeout(Duration::from_secs(3));
                reader.control.wake.close_for_test();
                stop_bounded(reader);
                assert!(matches!(
                    result,
                    Ok(UiEvent::InputFailure(
                        crate::session::LocalInputFailure::ReaderUnavailable
                    ))
                ));
            } else {
                stop_bounded(reader);
            }
        }
    }

    #[test]
    fn input_wake_reader_cancels_pressure_with_marker_and_guards_retained() {
        for fail in [false, true] {
            let (read, mut write) = UnixStream::pair().unwrap();
            let (tx, rx) = mpsc::channel();
            let reader = InputReader::start_fd(
                tx,
                read.as_raw_fd(),
                crate::input_ingress::IngressBudget::default(),
            )
            .unwrap();
            write.write_all(&vec![b'x'; 17 * 4096]).unwrap();
            let mut prefix = Vec::new();
            let marker = loop {
                match rx.recv_timeout(Duration::from_secs(3)).unwrap() {
                    UiEvent::Stdin(bytes) => prefix.push(bytes),
                    UiEvent::IngressBlocked(blocked) => break blocked,
                    other => panic!("unexpected event: {other:?}"),
                }
            };
            if fail {
                reader.control.wake.fail_next_notify();
            }
            stop_bounded(reader);
            // These still own the exact preceding input prefix when join ends.
            let retained = prefix.iter().map(|b| b.len()).sum::<usize>();
            assert!((64 * 1024 - 4095..=64 * 1024).contains(&retained));
            drop(prefix);
            assert!(marker.resolve());
        }
    }
    #[test]
    fn input_wake_ack_error_is_terminal_and_keeps_published_prefix_order() {
        let (read, mut write) = UnixStream::pair().unwrap();
        let (tx, rx) = mpsc::channel();
        let reader = InputReader::start_fd(
            tx,
            read.as_raw_fd(),
            crate::input_ingress::IngressBudget::default(),
        )
        .unwrap();
        let source: Vec<u8> = (0..17u8).flat_map(|byte| vec![byte; 4096]).collect();
        write.write_all(&source).unwrap();
        let mut prefix = Vec::new();
        let marker = loop {
            match rx.recv_timeout(Duration::from_secs(3)).unwrap() {
                UiEvent::Stdin(bytes) => prefix.push(bytes),
                UiEvent::IngressBlocked(marker) => break marker,
                other => panic!("unexpected prefix event: {other:?}"),
            }
        };
        let retained: Vec<u8> = prefix
            .iter()
            .flat_map(|bytes| bytes.as_slice())
            .copied()
            .collect();
        assert!((64 * 1024 - 4095..=64 * 1024).contains(&retained.len()));
        assert_eq!(retained, source[..retained.len()]);
        drop(prefix);
        reader.control.wake.fail_next_notify();
        assert!(marker.resolve());
        let mut trailing = Vec::new();
        let result = loop {
            match rx.recv_timeout(Duration::from_secs(3)) {
                Ok(UiEvent::Stdin(bytes)) => trailing.extend_from_slice(bytes.as_slice()),
                other => break other,
            }
        };
        reader.control.wake.close_for_test();
        stop_bounded(reader);
        assert!(matches!(
            result,
            Ok(UiEvent::InputFailure(
                crate::session::LocalInputFailure::ReaderUnavailable
            ))
        ));
        assert_eq!(
            trailing,
            source[retained.len()..retained.len() + trailing.len()]
        );
        assert!(
            trailing.len() <= 4096,
            "only the fenced read may precede the terminal failure"
        );
    }
    #[test]
    fn input_wake_cancellation_after_last_check_releases_both_parks() {
        for (pressure, hard_failure) in [(false, false), (true, false), (false, true), (true, true)]
        {
            let (read, mut write) = UnixStream::pair().unwrap();
            let (tx, rx) = mpsc::channel();
            let reader = InputReader::start_fd(
                tx,
                read.as_raw_fd(),
                crate::input_ingress::IngressBudget::default(),
            )
            .unwrap();
            let mut prefix = Vec::new();
            let mut marker = None;
            // First pin the idle wait after its last cancellation check.
            let (entered, resume) = reader.control.wake.arm_poll();
            reader.control.wake.notify().unwrap();
            let observed = entered.recv_timeout(Duration::from_secs(3));
            if observed.is_err() {
                let _ = resume.send(());
                stop_bounded(reader);
                panic!("reader never reached fixture poll barrier");
            }
            if pressure {
                // Arm the pressure wait before publishing the bytes. The first
                // wake-only turn may consume this hook, so release idle, feed
                // the prefix, then explicitly wake/arm the actual pressure wait.
                resume.send(()).unwrap();
                write.write_all(&vec![b'x'; 17 * 4096]).unwrap();
                loop {
                    match rx.recv_timeout(Duration::from_secs(3)).unwrap() {
                        UiEvent::Stdin(bytes) => prefix.push(bytes),
                        UiEvent::IngressBlocked(blocked) => {
                            marker = Some(blocked);
                            break;
                        }
                        other => panic!("unexpected event: {other:?}"),
                    }
                }
                let (entered, resume) = reader.control.wake.arm_poll();
                reader.control.wake.notify().unwrap();
                let observed = entered.recv_timeout(Duration::from_secs(3));
                // Remove the arm notification while the sole reader is
                // paused after its last cancel check. Only stop's new wake
                // can now release the upcoming indefinite poll.
                reader.control.wake.drain_paused_reader();
                if hard_failure {
                    reader.control.wake.fail_next_notify();
                }
                stop_bounded_at_poll(reader, Some(resume));
                assert!(observed.is_ok());
            } else {
                reader.control.wake.drain_paused_reader();
                if hard_failure {
                    reader.control.wake.fail_next_notify();
                }
                stop_bounded_at_poll(reader, Some(resume));
            }
            drop(marker);
            drop(prefix);
        }
    }
}
