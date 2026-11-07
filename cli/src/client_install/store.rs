//! Managed immutable generations and atomic activation.
use crate::releases::ClientImage;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{symlink, DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: u32,
    prefix: PathBuf,
    generation: String,
    target: String,
    version: String,
    binary_sha256: String,
    archive_sha256: String,
    source_commit: String,
}

/// A validated snapshot, never authority obtained by deserializing a receipt alone.
#[derive(Debug, Clone)]
pub struct ManagedInstallation {
    pub prefix: PathBuf,
    pub version: String,
    active_target: PathBuf,
    receipt: Receipt,
}
#[derive(Debug)]
pub struct InstalledClient {
    pub executable: PathBuf,
}

struct Prepared<'a> {
    bytes: &'a [u8],
    version: &'a str,
    target: &'a str,
    binary_sha256: String,
    archive_sha256: String,
    source_commit: &'a str,
    manifest: &'a [u8],
    bundle: &'a [u8],
}

fn refuse(message: &str) -> io::Error {
    io::Error::other(message)
}
pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// Resolve the home itself once (macOS permits system aliases), but never a
/// supplied prefix component. Every component below home is inspected separately.
pub fn normalize_prefix(home: &Path, prefix: &Path) -> io::Result<PathBuf> {
    let canonical_home = fs::canonicalize(home)?;
    let relative = prefix
        .strip_prefix(home)
        .or_else(|_| prefix.strip_prefix(&canonical_home))
        .map_err(|_| refuse("installation prefix must be inside your home directory"))?;
    if !relative
        .components()
        .all(|c| matches!(c, Component::Normal(_)))
        || relative.as_os_str().is_empty()
    {
        return Err(refuse(
            "installation prefix must name a directory below your home",
        ));
    }
    let prefix = canonical_home.join(relative);
    inspect_directories(&canonical_home, &prefix, false)?;
    Ok(prefix)
}

pub(super) fn preflight(home: &Path, prefix: &Path) -> io::Result<PathBuf> {
    let prefix = normalize_prefix(home, prefix)?;
    let home = fs::canonicalize(home)?;
    inspect_directories(&home, &prefix.join("bin"), false)?;
    inspect_directories(&home, &prefix.join("lib/qsh/generations"), false)?;
    Ok(prefix)
}

fn directory_ok(path: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir() || meta.uid() != uid() || meta.mode() & 0o022 != 0 {
        return Err(refuse(
            "installation directories must be owned by you, unwritable by others, and not symlinks",
        ));
    }
    Ok(())
}
fn inspect_directories(home: &Path, path: &Path, create: bool) -> io::Result<()> {
    directory_ok(home)?;
    let mut current = home.to_path_buf();
    for component in path
        .strip_prefix(home)
        .map_err(|_| refuse("path outside home"))?
        .components()
    {
        if !matches!(component, Component::Normal(_)) {
            return Err(refuse("invalid installation path"));
        }
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(_) => directory_ok(&current)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if !create {
                    return Ok(());
                }
                fs::DirBuilder::new().mode(0o700).create(&current)?;
                sync_dir(current.parent().unwrap())?;
                directory_ok(&current)?;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
fn regular(path: &Path, max: u64) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != uid()
        || meta.nlink() != 1
        || meta.mode() & 0o022 != 0
        || meta.len() > max
    {
        return Err(refuse(
            "invalid managed installation file ownership, links, permissions, or size",
        ));
    }
    Ok(file)
}
fn read_regular(path: &Path, max: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    regular(path, max)?.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(refuse("managed installation file size limit"));
    }
    Ok(bytes)
}
fn read_receipt(path: &Path) -> io::Result<Receipt> {
    serde_json::from_slice(&read_regular(path, 16 * 1024)?)
        .map_err(|_| refuse("invalid managed installation receipt"))
}
fn sync_dir(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}
fn write_new(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    file.sync_all()
}
fn active(prefix: &Path) -> PathBuf {
    prefix.join("bin/qsh")
}
fn active_link(prefix: &Path) -> io::Result<PathBuf> {
    let meta = fs::symlink_metadata(active(prefix))?;
    if !meta.file_type().is_symlink() || meta.uid() != uid() || meta.nlink() != 1 {
        return Err(refuse("qsh destination is not a registered active link"));
    }
    fs::read_link(active(prefix))
}

pub fn publish(
    home: &Path,
    prefix: &Path,
    image: &ClientImage,
    expected: Option<&ManagedInstallation>,
) -> io::Result<InstalledClient> {
    publish_cancellable(home, prefix, image, expected, &|| false)
}

pub fn publish_cancellable(
    home: &Path,
    prefix: &Path,
    image: &ClientImage,
    expected: Option<&ManagedInstallation>,
    cancelled: &dyn Fn() -> bool,
) -> io::Result<InstalledClient> {
    let manifest = image.manifest();
    publish_prepared_with_cancel(
        home,
        prefix,
        &Prepared {
            bytes: image.bytes(),
            version: &image.request().version,
            target: image.request().platform.target(),
            binary_sha256: hex(image.sha256()),
            archive_sha256: hex(image.archive_sha256()),
            source_commit: manifest.source_commit(),
            manifest: manifest.manifest_bytes(),
            bundle: manifest.bundle_bytes(),
        },
        expected,
        cancelled,
    )
}

#[cfg(test)]
fn publish_prepared(
    home: &Path,
    prefix: &Path,
    image: &Prepared<'_>,
    expected: Option<&ManagedInstallation>,
) -> io::Result<InstalledClient> {
    publish_prepared_with_cancel(home, prefix, image, expected, &|| false)
}

fn publish_prepared_with_cancel(
    home: &Path,
    prefix: &Path,
    image: &Prepared<'_>,
    expected: Option<&ManagedInstallation>,
    cancelled: &dyn Fn() -> bool,
) -> io::Result<InstalledClient> {
    let check_cancel = || {
        if cancelled() {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "client update canceled",
            ))
        } else {
            Ok(())
        }
    };
    check_cancel()?;
    let prefix = normalize_prefix(home, prefix)?;
    let home = fs::canonicalize(home)?;
    inspect_directories(&home, &prefix.join("bin"), true)?;
    let generations = prefix.join("lib/qsh/generations");
    inspect_directories(&home, &generations, true)?;
    let store = prefix.join("lib/qsh");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(store.join("install.lock"))?;
    let meta = lock.metadata()?;
    if !meta.is_file() || meta.uid() != uid() || meta.nlink() != 1 || meta.mode() & 0o077 != 0 {
        return Err(refuse("unsafe installation lock"));
    }
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| refuse("another installation is in progress; try again"))?;
    match expected {
        Some(previous) => {
            if previous.prefix != prefix || active_link(&prefix)? != previous.active_target {
                return Err(refuse(
                    "active installation changed while downloading; try again",
                ));
            }
            let generation = prefix.join("bin").join(&previous.active_target);
            if read_receipt(&generation.parent().unwrap().join("receipt.json"))? != previous.receipt
                || hex(&Sha256::digest(read_regular(
                    &generation,
                    32 * 1024 * 1024,
                )?)) != previous.receipt.binary_sha256
            {
                return Err(refuse("managed installation changed while downloading"));
            }
        }
        None => match fs::symlink_metadata(active(&prefix)) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            _ => {
                return Err(refuse(
                    "qsh destination already exists; it will not be overwritten",
                ))
            }
        },
    }
    if hex(&Sha256::digest(image.bytes)) != image.binary_sha256 {
        return Err(refuse("verified client digest changed"));
    }
    check_cancel()?;
    let staging = tempfile::Builder::new()
        .prefix("generation-")
        .tempdir_in(&generations)?;
    let generation = staging
        .path()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let receipt = Receipt {
        schema: 1,
        prefix: prefix.clone(),
        generation: generation.clone(),
        target: image.target.to_owned(),
        version: image.version.to_owned(),
        binary_sha256: image.binary_sha256.clone(),
        archive_sha256: image.archive_sha256.clone(),
        source_commit: image.source_commit.to_owned(),
    };
    write_new(&staging.path().join("qsh"), image.bytes, 0o555)?;
    write_new(
        &staging.path().join("receipt.json"),
        &serde_json::to_vec(&receipt)?,
        0o444,
    )?;
    write_new(&staging.path().join("SHA256SUMS"), image.manifest, 0o444)?;
    write_new(
        &staging.path().join("SHA256SUMS.sigstore.json"),
        image.bundle,
        0o444,
    )?;
    sync_dir(staging.path())?;
    let target = PathBuf::from("../lib/qsh/generations")
        .join(&generation)
        .join("qsh");
    // Keep before linking: cleanup must never remove a committed generation.
    // An interrupted attempt can leave an unreferenced generation, never a partial active one.
    check_cancel()?;
    let kept = staging.keep();
    sync_dir(&generations)?;
    let result = if let Err(error) = check_cancel() {
        Err(error)
    } else if expected.is_none() {
        symlink(&target, active(&prefix)) // Atomic create, fails if any destination appeared.
    } else {
        let temporary = prefix.join("bin").join(format!(".qsh-{generation}"));
        symlink(&target, &temporary)?;
        let result = check_cancel().and_then(|()| fs::rename(&temporary, active(&prefix)));
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    };
    if let Err(error) = result {
        let _ = fs::remove_dir_all(kept);
        return Err(error);
    }
    if sync_dir(&prefix.join("bin")).is_err() {
        return Err(refuse("installation committed, but directory sync failed; inspect the reported prefix before retrying"));
    }
    Ok(InstalledClient {
        executable: active(&prefix),
    })
}

/// Validate actual executable identity before any update network operation.
/// The receipt is checked against original signed evidence, never trusted alone.
pub fn validate_running(
    home: &Path,
    executable: &Path,
    version: &str,
    target: &str,
    source_commit: &str,
) -> io::Result<ManagedInstallation> {
    let executable = fs::canonicalize(executable)?;
    let generation = executable
        .parent()
        .ok_or_else(|| refuse("unregistered qsh executable"))?;
    let generations = generation
        .parent()
        .ok_or_else(|| refuse("unregistered qsh executable"))?;
    let store = generations
        .parent()
        .ok_or_else(|| refuse("unregistered qsh executable"))?;
    let lib = store
        .parent()
        .ok_or_else(|| refuse("unregistered qsh executable"))?;
    let prefix = lib
        .parent()
        .ok_or_else(|| refuse("unregistered qsh executable"))?;
    if executable.file_name().is_none_or(|s| s != "qsh")
        || generations.file_name().is_none_or(|s| s != "generations")
        || store.file_name().is_none_or(|s| s != "qsh")
        || lib.file_name().is_none_or(|s| s != "lib")
    {
        return Err(refuse("only a registered managed qsh can self-update; use your package manager or install a separate managed copy"));
    }
    let prefix = normalize_prefix(home, prefix)?;
    inspect_directories(&fs::canonicalize(home)?, &prefix.join("bin"), false)?;
    inspect_directories(&fs::canonicalize(home)?, generation, false)?;
    let receipt = read_receipt(&generation.join("receipt.json"))?;
    let name = generation
        .file_name()
        .unwrap()
        .to_str()
        .ok_or_else(|| refuse("invalid generation"))?;
    let expected = PathBuf::from("../lib/qsh/generations")
        .join(name)
        .join("qsh");
    if receipt.schema != 1
        || receipt.prefix != prefix
        || receipt.generation != name
        || receipt.version != version
        || receipt.target != target
        || receipt.source_commit != source_commit
        || active_link(&prefix)? != expected
        || fs::canonicalize(active(&prefix))? != executable
        || hex(&Sha256::digest(read_regular(
            &executable,
            32 * 1024 * 1024,
        )?)) != receipt.binary_sha256
    {
        return Err(refuse(
            "managed receipt, active executable, or build identity does not match",
        ));
    }
    let evidence = release_auth::verify_manifest(
        &receipt.version,
        &read_regular(
            &generation.join("SHA256SUMS"),
            release_auth::SUMS_LIMIT as u64,
        )?,
        &read_regular(
            &generation.join("SHA256SUMS.sigstore.json"),
            release_auth::BUNDLE_LIMIT as u64,
        )?,
    )
    .map_err(|_| refuse("managed installation release evidence is invalid"))?;
    let asset = format!("qsh-{}-{}.tar.gz", receipt.version, receipt.target);
    if evidence.source_commit() != receipt.source_commit
        || evidence.asset_hash(&asset).map(|h| hex(h)).as_deref()
            != Some(receipt.archive_sha256.as_str())
    {
        return Err(refuse(
            "managed receipt does not match signed release evidence",
        ));
    }
    Ok(ManagedInstallation {
        prefix,
        version: receipt.version.clone(),
        active_target: expected,
        receipt,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::symlink};
    struct Temp(PathBuf);
    impl Temp {
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn temp() -> Temp {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "qsh531-store-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Temp(path)
    }
    fn image() -> Prepared<'static> {
        Prepared {
            bytes: b"verified client fixture",
            version: "0.7.0",
            target: "x86_64-unknown-linux-musl",
            binary_sha256: hex(&Sha256::digest(b"verified client fixture")),
            archive_sha256: "archive fixture".into(),
            source_commit: "fixture",
            manifest: b"manifest fixture",
            bundle: b"bundle fixture",
        }
    }
    #[test]
    fn cancellation_before_each_publication_boundary_never_activates_a_generation() {
        for stop_at in 1..=4 {
            let home = temp();
            let prefix = home.path().join(".local");
            let checks = std::cell::Cell::new(0);
            let cancelled = || {
                checks.set(checks.get() + 1);
                checks.get() >= stop_at
            };
            let error =
                publish_prepared_with_cancel(home.path(), &prefix, &image(), None, &cancelled)
                    .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Interrupted);
            assert!(
                fs::symlink_metadata(active(&prefix)).is_err(),
                "cancellation at boundary{stop_at} activated a client"
            );
            if let Ok(generations) = fs::read_dir(prefix.join("lib/qsh/generations")) {
                assert_eq!(
                    generations.count(),
                    0,
                    "canceled staged generation must be cleaned"
                );
            }
        }
    }
    #[test]
    fn canceled_update_preserves_the_previous_active_generation() {
        for stop_at in 1..=5 {
            let home = temp();
            let prefix = home.path().join(".local");
            publish_prepared(home.path(), &prefix, &image(), None).unwrap();
            let previous = snapshot(&prefix);
            let before = active_link(&prefix).unwrap();
            let mut next = image();
            next.version = "0.7.1";
            let checks = std::cell::Cell::new(0);
            let cancelled = || {
                checks.set(checks.get() + 1);
                checks.get() >= stop_at
            };
            let error = publish_prepared_with_cancel(
                home.path(),
                &prefix,
                &next,
                Some(&previous),
                &cancelled,
            )
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Interrupted);
            assert_eq!(
                active_link(&prefix).unwrap(),
                before,
                "cancellation at boundary{stop_at} replaced the active client"
            );
            assert_eq!(
                fs::read_dir(prefix.join("lib/qsh/generations"))
                    .unwrap()
                    .count(),
                1
            );
        }
    }
    #[test]
    fn fresh_install_publishes_one_complete_generation() {
        let home = temp();
        let prefix = home.path().join(".local");
        let installed = publish_prepared(home.path(), &prefix, &image(), None).unwrap();
        assert_eq!(fs::read(&installed.executable).unwrap(), image().bytes);
        let generation = fs::canonicalize(&installed.executable).unwrap();
        assert!(generation.parent().unwrap().join("receipt.json").is_file());
    }
    #[test]
    fn occupied_destination_is_preserved() {
        let home = temp();
        let prefix = home.path().join(".local");
        fs::create_dir_all(prefix.join("bin")).unwrap();
        fs::write(prefix.join("bin/qsh"), b"foreign").unwrap();
        assert!(publish_prepared(home.path(), &prefix, &image(), None).is_err());
        assert_eq!(fs::read(prefix.join("bin/qsh")).unwrap(), b"foreign");
    }
    #[test]
    fn symlink_ancestor_cannot_redirect_installation() {
        let home = temp();
        let outside = temp();
        symlink(outside.path(), home.path().join("redirect")).unwrap();
        assert!(publish_prepared(
            home.path(),
            &home.path().join("redirect/prefix"),
            &image(),
            None
        )
        .is_err());
        assert!(!outside.path().join("prefix").exists());
    }
    #[test]
    fn outside_home_is_rejected_without_creation() {
        let home = temp();
        let outside = temp();
        assert!(
            publish_prepared(home.path(), &outside.path().join("prefix"), &image(), None).is_err()
        );
        assert!(!outside.path().join("prefix").exists());
    }
    fn snapshot(prefix: &Path) -> ManagedInstallation {
        let active_target = active_link(prefix).unwrap();
        let generation = prefix.join("bin").join(&active_target);
        let receipt = read_receipt(&generation.parent().unwrap().join("receipt.json")).unwrap();
        ManagedInstallation {
            prefix: receipt.prefix.clone(),
            version: receipt.version.clone(),
            active_target,
            receipt,
        }
    }
    #[test]
    fn update_switches_binary_and_receipt_together_and_retains_old_generation() {
        let home = temp();
        let prefix = home.path().join("prefix");
        let old = publish_prepared(home.path(), &prefix, &image(), None).unwrap();
        let old_path = fs::canonicalize(&old.executable).unwrap();
        let previous = snapshot(&prefix);
        let mut next = image();
        next.bytes = b"next verified client";
        next.version = "0.7.1";
        next.binary_sha256 = hex(&Sha256::digest(next.bytes));
        publish_prepared(home.path(), &prefix, &next, Some(&previous)).unwrap();
        assert_eq!(
            fs::read(prefix.join("bin/qsh")).unwrap(),
            b"next verified client"
        );
        assert_eq!(snapshot(&prefix).version, "0.7.1");
        assert_eq!(fs::read(old_path).unwrap(), b"verified client fixture");
    }
    #[test]
    fn stale_update_cannot_replace_a_newer_generation() {
        let home = temp();
        let prefix = home.path().join("prefix");
        publish_prepared(home.path(), &prefix, &image(), None).unwrap();
        let previous = snapshot(&prefix);
        publish_prepared(home.path(), &prefix, &image(), Some(&previous)).unwrap();
        let newer = fs::read_link(prefix.join("bin/qsh")).unwrap();
        assert!(publish_prepared(home.path(), &prefix, &image(), Some(&previous)).is_err());
        assert_eq!(fs::read_link(prefix.join("bin/qsh")).unwrap(), newer);
    }
    #[test]
    fn modified_receipt_and_hardlinked_binary_refuse_publication() {
        let home = temp();
        let prefix = home.path().join("prefix");
        publish_prepared(home.path(), &prefix, &image(), None).unwrap();
        let previous = snapshot(&prefix);
        let exe = fs::canonicalize(prefix.join("bin/qsh")).unwrap();
        fs::hard_link(&exe, home.path().join("hardlink")).unwrap();
        assert!(publish_prepared(home.path(), &prefix, &image(), Some(&previous)).is_err());
        fs::remove_file(home.path().join("hardlink")).unwrap();
        fs::set_permissions(
            exe.parent().unwrap().join("receipt.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fs::write(exe.parent().unwrap().join("receipt.json"), b"{}").unwrap();
        assert!(publish_prepared(home.path(), &prefix, &image(), Some(&previous)).is_err());
        assert_eq!(
            fs::read(prefix.join("bin/qsh")).unwrap(),
            b"verified client fixture"
        );
    }
    #[test]
    fn competing_first_install_never_overwrites_winner() {
        let home = temp();
        let prefix = home.path().join("prefix");
        // Prepare directories so the race reaches the lock/publication boundary.
        inspect_directories(home.path(), &prefix.join("lib/qsh/generations"), true).unwrap();
        inspect_directories(home.path(), &prefix.join("bin"), true).unwrap();
        let results = std::thread::scope(|scope| {
            let a = scope.spawn(|| publish_prepared(home.path(), &prefix, &image(), None));
            let b = scope.spawn(|| publish_prepared(home.path(), &prefix, &image(), None));
            [a.join().unwrap().is_ok(), b.join().unwrap().is_ok()]
        });
        assert_eq!(results.into_iter().filter(|ok| *ok).count(), 1);
        assert_eq!(
            fs::read(prefix.join("bin/qsh")).unwrap(),
            b"verified client fixture"
        );
    }
    #[test]
    fn interrupted_generation_is_never_selected_and_bad_digest_preserves_active() {
        let home = temp();
        let prefix = home.path().join("prefix");
        publish_prepared(home.path(), &prefix, &image(), None).unwrap();
        let previous = snapshot(&prefix);
        let old = fs::read_link(prefix.join("bin/qsh")).unwrap();
        fs::create_dir(prefix.join("lib/qsh/generations/interrupted")).unwrap();
        fs::write(
            prefix.join("lib/qsh/generations/interrupted/qsh"),
            b"partial",
        )
        .unwrap();
        let mut bad = image();
        bad.bytes = b"corrupt";
        assert!(publish_prepared(home.path(), &prefix, &bad, Some(&previous)).is_err());
        assert_eq!(fs::read_link(prefix.join("bin/qsh")).unwrap(), old);
    }

    #[test]
    fn redirected_bin_is_rejected_before_release_evidence() {
        let home = temp();
        let prefix = home.path().join("prefix");
        publish_prepared(home.path(), &prefix, &image(), None).unwrap();
        let executable = fs::canonicalize(prefix.join("bin/qsh")).unwrap();
        let moved = home.path().join("moved-bin");
        fs::rename(prefix.join("bin"), &moved).unwrap();
        symlink(&moved, prefix.join("bin")).unwrap();
        let error = validate_running(
            home.path(),
            &executable,
            "0.7.0",
            "x86_64-unknown-linux-musl",
            "fixture",
        )
        .unwrap_err();
        assert!(error.to_string().contains("directories"));
    }
    #[test]
    fn home_alias_update_uses_canonical_receipt_identity() {
        let root = temp();
        let actual_home = root.path().join("actual-home");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&actual_home)
            .unwrap();
        let alias_home = root.path().join("home-alias");
        symlink(&actual_home, &alias_home).unwrap();
        let prefix = alias_home.join("prefix");
        publish_prepared(&alias_home, &prefix, &image(), None).unwrap();
        let previous = snapshot(&prefix);
        let old = fs::canonicalize(prefix.join("bin/qsh")).unwrap();
        let mut next = image();
        next.bytes = b"updated through home alias";
        next.version = "0.7.1";
        next.binary_sha256 = hex(&Sha256::digest(next.bytes));
        publish_prepared(&alias_home, &prefix, &next, Some(&previous)).unwrap();
        assert_eq!(
            snapshot(&prefix).prefix,
            fs::canonicalize(actual_home.join("prefix")).unwrap()
        );
        assert_eq!(
            fs::read(prefix.join("bin/qsh")).unwrap(),
            b"updated through home alias"
        );
        assert_eq!(fs::read(old).unwrap(), b"verified client fixture");
    }
}
