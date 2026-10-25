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
//! Append errors are swallowed. The fallible startup API lets callers report a
//! disabled sink without making logging a requirement for their work.

use crate::file_path::{Intent, ParentAuthority};
#[cfg(test)]
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

pub struct FileSink {
    inner: Mutex<Inner>,
}

struct Inner {
    authority: ParentAuthority,
    max_bytes: u64,
    file: File,
    #[cfg(test)]
    before_active_check: Option<Box<dyn FnOnce() + Send>>,
    // One-shot owned phase gate for the actual concurrent preflight test.
    #[cfg(test)]
    before_append: Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>,
}

impl FileSink {
    /// Opens a log under a declared dedicated application directory. Only that
    /// current-account-owned final directory may be repaired to private mode.
    pub fn open_in_private_dir(path: &Path, max_bytes: u64) -> Option<FileSink> {
        Self::try_open_in_private_dir(path, max_bytes).ok()
    }

    /// Opens a validated append target, creating missing components privately.
    /// Existing generic parents are never chmodded, even when owned by us.
    pub fn open(path: &Path, max_bytes: u64) -> Option<FileSink> {
        Self::open_with_intent(path, max_bytes, Intent::Generic)
    }

    /// Fallible startup API: the caller can surface why its file sink is disabled.
    pub fn try_open_in_private_dir(path: &Path, max_bytes: u64) -> std::io::Result<FileSink> {
        Self::try_open_with_intent(path, max_bytes, Intent::DeclaredPrivate)
    }

    fn open_with_intent(path: &Path, max_bytes: u64, intent: Intent) -> Option<FileSink> {
        Self::try_open_with_intent(path, max_bytes, intent).ok()
    }

    fn try_open_with_intent(
        path: &Path,
        max_bytes: u64,
        intent: Intent,
    ) -> std::io::Result<FileSink> {
        let authority = ParentAuthority::resolve(path, intent, true)?;
        let file = authority
            .open_append_checked()
            .map_err(|error| crate::path_error(path, "opening log file", error))?;
        Ok(FileSink {
            inner: Mutex::new(Inner {
                authority,
                max_bytes,
                file,
                #[cfg(test)]
                before_append: None,
                #[cfg(test)]
                before_active_check: None,
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

    #[cfg(test)]
    pub(crate) fn before_active_check_once(&self, action: impl FnOnce() + Send + 'static) {
        self.inner.lock().unwrap().before_active_check = Some(Box::new(action));
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
        let Ok(changed) = self.authority.refresh_route() else {
            return false;
        };
        if changed && !self.reopen() {
            return false;
        }
        #[cfg(test)]
        if let Some(action) = self.before_active_check.take() {
            action();
        }
        match self.authority.owns_active(&self.file) {
            Ok(true) => {}
            Ok(false) if self.reopen() => {}
            _ => return false,
        }
        let Ok(metadata) = self.file.metadata() else {
            return false;
        };
        if self.fits(metadata.len(), bytes) {
            return true;
        }
        if self.authority.rotate_checked(&self.file).is_err() {
            return false;
        }
        // A raced rotation may already have installed another file. Reopen
        // either way; never fall back to the descriptor that did not fit.
        if !self.reopen() {
            return false;
        }
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

    fn reopen(&mut self) -> bool {
        let Ok(authority) = self.authority.reopen_route() else {
            return false;
        };
        match authority.open_append_checked() {
            Ok(file) => {
                self.file = file;
                self.authority = authority;
                true
            }
            Err(_) => false,
        }
    }
}

#[cfg(test)]
#[path = "file_tests.rs"]
mod tests;
