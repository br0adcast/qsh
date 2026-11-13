//! Fixed-size, private actor evidence independent of the controlling PTY.
use super::fixture_gate::exclusive;
use nix::libc;
use std::fs::File;
use std::io;
use std::os::unix::{
    fs::{FileExt, MetadataExt, OpenOptionsExt},
    io::AsRawFd,
};
use std::path::Path;
use std::sync::Arc;

const INITIAL: &[u8; 16] = b"KAD1\0\0\0\0\0\0\0\0\0\0\0\0";
const STAGES: [&str; 10] = [
    "unobserved",
    "opened",
    "ready",
    "kill-session",
    "session-killed",
    "fork-gate",
    "spawn-late",
    "late-created",
    "exit-gate",
    "exit37",
];
const READS: [&str; 5] = ["unobserved", "missing", "valid", "mismatch", "refused"];
const SOURCES: [&str; 5] = ["none", "keeper-tests", "gate", "diagnostics", "other"];

#[derive(Clone, Copy)]
#[repr(u8)]
pub(super) enum Stage {
    Opened = 1,
    Ready,
    KillSession,
    SessionKilled,
    ForkGate,
    SpawnLate,
    LateCreated,
    ExitGate,
    Exit37,
}
#[derive(Clone, Copy)]
#[repr(u8)]
pub(super) enum GateRead {
    Missing = 1,
    Valid,
    Mismatch,
    Refused,
}

pub(super) struct Evidence(File);
impl Evidence {
    pub(super) fn create(path: &Path) -> io::Result<File> {
        exclusive(path, INITIAL)?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        validate(&file)?;
        Ok(file)
    }
    pub(super) fn open(path: &Path) -> io::Result<Arc<Self>> {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        validate(&file)?;
        Ok(Arc::new(Self(file)))
    }
    pub(super) fn stage(&self, stage: Stage) {
        self.write(&[stage as u8, 0], 4);
    }
    pub(super) fn read(&self, result: GateRead) {
        self.write(&[result as u8], 5);
    }
    fn write(&self, bytes: &[u8], offset: i64) {
        // One bounded best-effort syscall; evidence must never replace actor assertions.
        unsafe {
            libc::pwrite(
                self.0.as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
                offset,
            );
        }
    }
    pub(super) fn install(self: &Arc<Self>) {
        let evidence = Arc::clone(self);
        std::panic::set_hook(Box::new(move |info| {
            if let Some(location) = info.location() {
                evidence.panic_at(location);
            }
        }));
    }
    fn panic_at(&self, location: &std::panic::Location<'_>) {
        let source = if location.file().ends_with("/keeper_tests.rs") {
            1
        } else if location.file().ends_with("/keeper_fixture_gate.rs") {
            2
        } else if location.file().ends_with("/keeper_fixture_diagnostics.rs") {
            3
        } else {
            4
        };
        let mut bytes = [0; 10];
        bytes[0] = source;
        bytes[2..6].copy_from_slice(&location.line().to_le_bytes());
        bytes[6..10].copy_from_slice(&location.column().to_le_bytes());
        self.write(&bytes, 6);
    }
}
fn validate(file: &File) -> io::Result<()> {
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o777 != 0o600
        || meta.len() != 16
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(())
}
pub(super) fn report(file: &File) -> String {
    let receipt = (|| {
        validate(file).ok()?;
        let mut bytes = [0; 16];
        file.read_exact_at(&mut bytes, 0).ok()?;
        if bytes[..4] != INITIAL[..4] || bytes[7] != 0 {
            return None;
        }
        let stage = *STAGES.get(bytes[4] as usize)?;
        let read = *READS.get(bytes[5] as usize)?;
        let source = *SOURCES.get(bytes[6] as usize)?;
        let line = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
        let column = u32::from_le_bytes(bytes[12..16].try_into().ok()?);
        if bytes[6] == 0 && (line != 0 || column != 0) {
            return None;
        }
        Some(format!("keeper223 actor_diag available=true stage={stage} read={read} panic_file={source} panic_line={line} panic_column={column}"))
    })();
    receipt.unwrap_or_else(|| "keeper223 actor_diag available=false reason=invalid".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actor_receipt_survives_stdio_loss_and_reports_only_fixed_fields() {
        const CHILD: &str = "QSH_KEEPER_RECEIPT_CHILD";
        if let Some(path) = std::env::var_os(CHILD) {
            let evidence = Evidence::open(Path::new(&path)).unwrap();
            evidence.install();
            evidence.stage(Stage::ExitGate);
            evidence.read(GateRead::Mismatch);
            for fd in 0..3 {
                unsafe {
                    libc::close(fd);
                }
            }
            let _ = std::panic::catch_unwind(|| panic!("fixture-private-payload"));
            std::process::exit(101);
        }
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("actor");
        let reader = Evidence::create(&path).unwrap();
        let selector = concat!(
            module_path!(),
            "::actor_receipt_survives_stdio_loss_and_reports_only_fixed_fields"
        );
        let selector = selector.split_once("::").unwrap().1;
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", selector, "--nocapture"])
            .env(CHILD, &path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if std::time::Instant::now() >= end {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("receipt child exceeded deadline");
            }
            std::thread::yield_now();
        };
        assert_eq!(status.code(), Some(101));
        let receipt = report(&reader);
        assert!(
            receipt.contains("stage=exit-gate read=mismatch panic_file=diagnostics panic_line="),
            "{receipt}"
        );
        assert!(!receipt.contains("fixture-private-payload"));
        assert_eq!(reader.metadata().unwrap().len(), 16);
    }
    #[test]
    fn corrupt_receipts_never_echo_input() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("actor");
        let reader = Evidence::create(&path).unwrap();
        let writer = Evidence::open(&path).unwrap();
        for offset in [0, 4, 5, 6, 7] {
            writer.0.write_all_at(INITIAL, 0).unwrap();
            writer.0.write_all_at(&[255], offset).unwrap();
            assert_eq!(
                report(&reader),
                "keeper223 actor_diag available=false reason=invalid"
            );
        }
        writer.0.write_all_at(&[0; 17], 0).unwrap();
        assert_eq!(
            report(&reader),
            "keeper223 actor_diag available=false reason=invalid"
        );
    }
    #[test]
    fn typed_stage_and_read_updates_remain_fixed_size() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("actor");
        let reader = Evidence::create(&path).unwrap();
        let evidence = Evidence::open(&path).unwrap();
        for stage in [
            Stage::Opened,
            Stage::Ready,
            Stage::KillSession,
            Stage::SessionKilled,
            Stage::ForkGate,
            Stage::SpawnLate,
            Stage::LateCreated,
            Stage::ExitGate,
            Stage::Exit37,
        ] {
            evidence.stage(stage);
            assert!(report(&reader).contains(STAGES[stage as usize]));
        }
        for result in [
            GateRead::Missing,
            GateRead::Valid,
            GateRead::Mismatch,
            GateRead::Refused,
        ] {
            evidence.read(result);
            assert!(report(&reader).contains(READS[result as usize]));
        }
        evidence.stage(Stage::ExitGate);
        assert!(report(&reader).contains("stage=exit-gate read=unobserved"));
        assert_eq!(reader.metadata().unwrap().len(), 16);
    }
}
