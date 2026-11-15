//! Test-only ordering between actual fixture input and actor release.
use std::io::{self, Write};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::time::Instant;

pub(super) const FIXTURE_INPUT: &[u8] = b"fixture-input\n";

pub(super) fn write_fixture_input(writer: &mut impl Write, accepted: Sender<()>) -> io::Result<()> {
    let result = writer.write_all(FIXTURE_INPUT);
    if result.is_ok() {
        let _ = accepted.send(());
    }
    result
}

pub(super) fn release_after_input(
    accepted: &Receiver<()>,
    deadline: Instant,
    release: impl FnOnce(),
) -> Result<(), RecvTimeoutError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(RecvTimeoutError::Timeout)?;
    accepted.recv_timeout(remaining)?;
    if Instant::now() >= deadline {
        return Err(RecvTimeoutError::Timeout);
    }
    release();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::sync::mpsc::{channel, TryRecvError};
    use std::time::Duration;

    const GUARD: Duration = Duration::from_secs(30);

    struct GatedWrite {
        bytes: Vec<u8>,
        entered: Sender<()>,
        finish: Receiver<()>,
    }

    impl Write for GatedWrite {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.bytes.is_empty() {
                self.bytes.extend_from_slice(&bytes[..3]);
                return Ok(3);
            }
            self.entered
                .send(())
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
            self.finish
                .recv_timeout(GUARD)
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn input_ack_waits_for_complete_successful_write() {
        let (accepted, receipt) = channel();
        let (entered, writing) = channel();
        let (finish, resumed) = channel();
        let worker = std::thread::spawn(move || {
            let mut writer = GatedWrite {
                bytes: Vec::new(),
                entered,
                finish: resumed,
            };
            let result = write_fixture_input(&mut writer, accepted);
            (writer.bytes, result)
        });
        let entered_result = writing.recv_timeout(GUARD);
        let blocked_receipt = receipt.try_recv();
        // Release and join even when the observations are about to fail.
        let resume_result = finish.send(());
        let joined = worker.join();
        assert!(entered_result.is_ok(), "partial write entered");
        assert!(resume_result.is_ok(), "owned writer released");
        let (bytes, result) = joined.expect("owned writer joined");
        result.expect("complete fixture input accepted");
        assert_eq!(bytes, b"fixture-input\n");
        assert!(matches!(blocked_receipt, Err(TryRecvError::Empty)));
        assert_eq!(receipt.recv_timeout(GUARD), Ok(()));
        assert_eq!(receipt.try_recv(), Err(TryRecvError::Disconnected));
    }

    struct PartialError(Vec<u8>);

    impl Write for PartialError {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.0.is_empty() {
                self.0.extend_from_slice(&bytes[..3]);
                Ok(3)
            } else {
                Err(io::Error::from_raw_os_error(5))
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn write_error_never_releases_actor() {
        let (accepted, receipt) = channel();
        let mut writer = PartialError(Vec::new());
        let result = write_fixture_input(&mut writer, accepted);
        let releases = Cell::new(0);
        let release_result = release_after_input(&receipt, Instant::now() + GUARD, || {
            releases.set(releases.get() + 1);
        });
        assert_eq!(writer.0, b"fix");
        assert_eq!(result.unwrap_err().raw_os_error(), Some(5));
        assert_eq!(release_result, Err(RecvTimeoutError::Disconnected));
        assert_eq!(releases.get(), 0);
    }

    struct PanickingWrite;

    impl Write for PanickingWrite {
        fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            panic!("injected writer panic");
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn writer_panic_never_releases_actor() {
        let (accepted, receipt) = channel();
        let worker = std::thread::spawn(move || write_fixture_input(&mut PanickingWrite, accepted));
        let joined = worker.join();
        let releases = Cell::new(0);
        let result = release_after_input(&receipt, Instant::now() + GUARD, || {
            releases.set(releases.get() + 1);
        });
        assert!(joined.is_err(), "actual writer panic retained");
        assert_eq!(result, Err(RecvTimeoutError::Disconnected));
        assert_eq!(releases.get(), 0);
    }

    #[test]
    fn missing_or_expired_input_never_releases_actor() {
        let releases = Cell::new(0);
        let release = || releases.set(releases.get() + 1);
        let (accepted, receipt) = channel();
        drop(accepted);
        assert_eq!(
            release_after_input(&receipt, Instant::now() + GUARD, release),
            Err(RecvTimeoutError::Disconnected)
        );
        let (_pending, receipt) = channel();
        assert_eq!(
            release_after_input(&receipt, Instant::now(), release),
            Err(RecvTimeoutError::Timeout)
        );
        let (accepted, receipt) = channel();
        accepted.send(()).unwrap();
        drop(accepted);
        assert_eq!(
            release_after_input(&receipt, Instant::now(), release),
            Err(RecvTimeoutError::Timeout)
        );
        assert_eq!(releases.get(), 0);
    }

    #[test]
    fn accepted_input_releases_once_and_preserves_writer_result() {
        let (accepted, receipt) = channel();
        let worker = std::thread::spawn(move || {
            let mut writer = Vec::new();
            let result = write_fixture_input(&mut writer, accepted);
            (writer, result)
        });
        let releases = Cell::new(0);
        let first = release_after_input(&receipt, Instant::now() + GUARD, || {
            releases.set(releases.get() + 1);
        });
        let joined = worker.join();
        let second = release_after_input(&receipt, Instant::now() + GUARD, || {
            releases.set(releases.get() + 1);
        });
        let (bytes, result) = joined.expect("actual writer joined separately from receipt");
        result.expect("original successful write result");
        assert_eq!(bytes, b"fixture-input\n");
        assert_eq!(first, Ok(()));
        assert_eq!(second, Err(RecvTimeoutError::Disconnected));
        assert_eq!(releases.get(), 1);
    }
}
