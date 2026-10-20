//! A rotating append-only file sink that stays whole-line safe when several
//! processes (or sinks) share one path.
//!
//! Each complete record is appended with `write_all` on an `O_APPEND`
//! descriptor. Failed preparation drops the record instead of extending an old
//! inode indefinitely; later records retry. Oversized records are dropped whole.
//!
//! The mutex bounds a single sink's appends by its configured threshold.
//! Independent sinks can race preflight and append: for N cooperating writers
//! with threshold B and maximum encoded record L <= B, the conservative inode
//! bound is max(initial size, B + (N - 1) * L), at worst max(initial size, N * B).
//! This assumes regular-file metadata/append semantics and no outside writes;
//! it is not a writer-count-independent cap or transactional I/O guarantee.
//! Errors are swallowed: a log must never fail its caller.

use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub struct FileSink {
    inner: Mutex<Inner>,
}

struct Inner {
    path: PathBuf,
    rotated: PathBuf,
    max_bytes: u64,
    file: File,
    // One-shot owned phase gate for the actual concurrent preflight test.
    #[cfg(test)]
    before_append: Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>,
}

fn open_append(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)
}

impl FileSink {
    /// Opens (creating dir 0700 / file 0600) for appending; None when it cannot.
    pub fn open(path: &Path, max_bytes: u64) -> Option<FileSink> {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .ok()?;
        }
        let file = open_append(path).ok()?;
        // Tighten a pre-existing file and its directory; failure is ignored.
        if let Ok(m) = file.metadata() {
            if m.mode() & 0o077 != 0 {
                let _ = file.set_permissions(Permissions::from_mode(0o600));
            }
        }
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            if let Ok(m) = fs::metadata(dir) {
                if m.mode() & 0o077 != 0 {
                    let _ = fs::set_permissions(dir, Permissions::from_mode(0o700));
                }
            }
        }
        let mut rotated = path.as_os_str().to_owned();
        rotated.push(".1");
        Some(FileSink {
            inner: Mutex::new(Inner {
                path: path.to_path_buf(),
                rotated: PathBuf::from(rotated),
                max_bytes,
                file,
                #[cfg(test)]
                before_append: None,
            }),
        })
    }

    /// Appends whole records, rotating to "<path>.1" before exceeding the threshold.
    /// Records larger than the threshold (including newline), or whose target
    /// cannot be prepared, are dropped. A later record retries preparation.
    /// Zero disables appends. Independent writers have the bound described above.
    pub fn write_lines(&self, lines: &[String]) {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        for line in lines {
            inner.write_line(line);
        }
    }

    /// A clone of the open file, for code that needs a raw fd (tests).
    pub fn try_clone_file(&self) -> Option<File> {
        self.inner.lock().ok()?.file.try_clone().ok()
    }
}

impl Inner {
    fn write_line(&mut self, line: &str) {
        let Some(size) = line.len().checked_add(1) else {
            return;
        };
        let Ok(bytes) = u64::try_from(size) else {
            return;
        };
        if bytes > self.max_bytes || !self.prepare(bytes) {
            return;
        }
        #[cfg(test)]
        if let Some((entered, released)) = self.before_append.take() {
            let _ = entered.send(());
            let _ = released.recv();
        }
        let mut buf = Vec::with_capacity(size);
        buf.extend_from_slice(line.as_bytes());
        buf.push(b'\n');
        let _ = self.file.write_all(&buf);
    }

    /// Follows other rotations, then admits only a complete fitting record.
    fn prepare(&mut self, bytes: u64) -> bool {
        if !self.owns_path() && !self.reopen() {
            return false;
        }
        let Ok(metadata) = self.file.metadata() else {
            return false;
        };
        if self.fits(metadata.len(), bytes) {
            return true;
        }
        if self.owns_path() && fs::rename(&self.path, &self.rotated).is_err() {
            return false;
        }
        // A raced rotation may already have installed another file. Reopen
        // either way; never fall back to the descriptor that did not fit.
        if !self.reopen() {
            return false;
        }
        // Another writer may have filled the reopened file. Drop this record
        // rather than loop, truncate, or append past the observed threshold.
        self.file
            .metadata()
            .map(|m| self.fits(m.len(), bytes))
            .unwrap_or(false)
    }

    fn fits(&self, current: u64, bytes: u64) -> bool {
        current
            .checked_add(bytes)
            .is_some_and(|next| next <= self.max_bytes)
    }

    /// Whether the path still names the file we hold open.
    fn owns_path(&self) -> bool {
        match (fs::metadata(&self.path), self.file.metadata()) {
            (Ok(p), Ok(f)) => p.dev() == f.dev() && p.ino() == f.ino(),
            _ => false,
        }
    }

    fn reopen(&mut self) -> bool {
        match open_append(&self.path) {
            Ok(file) => {
                self.file = file;
                true
            }
            Err(_) => false,
        }
    }
}

#[cfg(test)]
#[path = "file_tests.rs"]
mod tests;
