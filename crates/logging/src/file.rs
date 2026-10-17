//! A rotating append-only file sink that stays whole-line safe when several
//! processes (or sinks) share one path.
//!
//! Every line is one `write_all` on an `O_APPEND` descriptor, so concurrent
//! writers interleave by line. Before each write the sink checks whether
//! someone else rotated the file (the path now names a different inode, or
//! none) and, if so, reopens the path instead of writing into the rotated
//! file. Only the writer that still owns the path's inode renames it.
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
            }),
        })
    }

    /// Writes the lines, one write_all each; rotates to "<path>.1" past max_bytes.
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
        self.prepare();
        let mut buf = Vec::with_capacity(line.len() + 1);
        buf.extend_from_slice(line.as_bytes());
        buf.push(b'\n');
        let _ = self.file.write_all(&buf);
    }

    /// Follows a rotation done by someone else, and rotates when full.
    fn prepare(&mut self) {
        if !self.owns_path() {
            self.reopen();
        }
        let full = self
            .file
            .metadata()
            .map(|m| m.len() >= self.max_bytes)
            .unwrap_or(false);
        if full && self.owns_path() {
            let _ = fs::rename(&self.path, &self.rotated);
            self.reopen();
        } else if full {
            // Raced with another rotation: the path already holds a fresh file.
            self.reopen();
        }
    }

    /// Whether the path still names the file we hold open.
    fn owns_path(&self) -> bool {
        match (fs::metadata(&self.path), self.file.metadata()) {
            (Ok(p), Ok(f)) => p.dev() == f.dev() && p.ino() == f.ino(),
            _ => false,
        }
    }

    fn reopen(&mut self) {
        if let Ok(f) = open_append(&self.path) {
            self.file = f;
        }
    }
}
