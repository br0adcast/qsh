//! Shared build-script inputs for Git identities, including linked worktrees.
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct GitMetadata {
    root: Option<PathBuf>,
    watches: BTreeSet<PathBuf>,
}

impl GitMetadata {
    pub fn commit_epoch(&self) -> Option<u64> {
        git(self.root.as_deref()?, &["log", "-1", "--format=%ct"])?
            .parse()
            .ok()
    }
}

fn git(root: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8(output.stdout).ok()?.trim().to_owned())
}

fn git_path(root: &Path, argument: &str) -> Option<PathBuf> {
    let path = PathBuf::from(git(root, &["rev-parse", argument])?);
    root.join(path).canonicalize().ok()
}

// Cargo treats a nonexistent watch as permanently dirty. Watching the nearest
// existing Git ancestor also detects creation of an optional packed/loose ref.
// Never ascend past the metadata root into the source tree (and Cargo outputs).
fn watch_existing(watches: &mut BTreeSet<PathBuf>, root: &Path, path: &Path) {
    let mut candidate = path;
    while candidate.starts_with(root) {
        if candidate.exists() {
            watches.insert(candidate.to_owned());
            return;
        }
        let Some(parent) = candidate.parent() else {
            return;
        };
        candidate = parent;
    }
}

// Git may be absent from a source builder's PATH. Follow only explicit,
// existing indirections in that case, without assigning them a commit identity.
fn fallback_watches(root: &Path, marker: &Path, watches: &mut BTreeSet<PathBuf>) {
    let git_dir = if marker.is_dir() {
        marker.canonicalize().ok()
    } else {
        std::fs::read_to_string(marker).ok().and_then(|contents| {
            let target = contents.trim().strip_prefix("gitdir:")?.trim();
            if target.is_empty() {
                return None;
            }
            root.join(target).canonicalize().ok()
        })
    };
    let Some(git_dir) = git_dir.filter(|path| path.is_dir() && !root.starts_with(path)) else {
        return;
    };
    watches.insert(git_dir.clone());
    let common = std::fs::read_to_string(git_dir.join("commondir"))
        .ok()
        .filter(|contents| !contents.trim().is_empty())
        .and_then(|contents| git_dir.join(contents.trim()).canonicalize().ok());
    if let Some(common) = common.filter(|path| path.is_dir() && !root.starts_with(path)) {
        watches.insert(common);
    }
}

fn resolve(root: &Path) -> Option<GitMetadata> {
    let root = root.canonicalize().ok()?;
    let marker = root.join(".git");
    // In particular, an archive inside another repository is still an archive.
    if !marker.exists() {
        return None;
    }
    let mut watches = BTreeSet::new();
    watches.insert(marker.clone());
    let context = (|| {
        if git_path(&root, "--show-toplevel")? != root {
            return None;
        }
        Some((
            git_path(&root, "--absolute-git-dir")?,
            git_path(&root, "--git-common-dir")?,
        ))
    })();
    let Some((git_dir, common_dir)) = context else {
        // A present marker remains an observable input when Git is unavailable
        // or the repository cannot be read. Do not borrow a parent identity.
        fallback_watches(&root, &marker, &mut watches);
        return Some(GitMetadata {
            root: None,
            watches,
        });
    };
    for (directory, names) in [
        (&git_dir, &["HEAD", "commondir", "refs"][..]),
        (&common_dir, &["refs", "packed-refs"][..]),
    ] {
        for name in names {
            watch_existing(&mut watches, directory, &directory.join(name));
        }
    }
    Some(GitMetadata {
        root: Some(root),
        watches,
    })
}

pub fn watch_git_metadata(root: &Path) -> Option<GitMetadata> {
    let metadata = resolve(root)?;
    for path in &metadata.watches {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    Some(metadata)
}
