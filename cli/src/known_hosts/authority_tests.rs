use std::io::Write;

// Owned SSH trust-store fixtures; no personal SSH state is used.
fn authority_dir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}
fn authority_write(path: impl AsRef<std::path::Path>, bytes: impl AsRef<[u8]>) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(&path, bytes)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}
fn authority_file(path: &std::path::Path, bytes: impl AsRef<[u8]>) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
}

#[test]
fn ssh_host_authority_reads_refuse_unsafe_and_special_evidence() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    for system_fails in [false, true] {
        for unsafe_parent in [false, true] {
            let dir = authority_dir();
            let user_dir = dir.path().join("user");
            let system_dir = dir.path().join("system");
            std::fs::create_dir(&user_dir).unwrap();
            std::fs::create_dir(&system_dir).unwrap();
            for parent in [&user_dir, &system_dir] {
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            let user = user_dir.join("known_hosts");
            let system = system_dir.join("known_hosts");
            authority_file(&user, line("h", K1));
            authority_file(&system, format!("@revoked {}", line("h", K1)));
            let failed = if system_fails { &system } else { &user };
            let unsafe_path = if unsafe_parent {
                failed.parent().unwrap()
            } else {
                failed.as_path()
            };
            std::fs::set_permissions(
                unsafe_path,
                std::fs::Permissions::from_mode(if unsafe_parent { 0o777 } else { 0o666 }),
            )
            .unwrap();
            let before = std::fs::metadata(unsafe_path).unwrap();
            let error = KnownHosts::new(user.clone(), Some(system.clone()))
                .lookup("h", 22)
                .unwrap_err();
            assert_eq!(&error.path, failed);
            assert_eq!(error.source.kind(), io::ErrorKind::PermissionDenied);
            let after = std::fs::metadata(unsafe_path).unwrap();
            assert_eq!(
                (before.dev(), before.ino(), before.mode()),
                (after.dev(), after.ino(), after.mode())
            );
        }
    }
    let dir = authority_dir();
    let missing = dir.path().join("absent/known_hosts");
    assert_eq!(
        KnownHosts::new(missing.clone(), None)
            .lookup("h", 22)
            .unwrap(),
        HostKeys::default()
    );
    assert!(!missing.parent().unwrap().exists());
    let fifo = dir.path().join("fifo");
    nix::unistd::mkfifo(
        &fifo,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();
    let socket = dir.path().join("socket");
    let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    for path in [fifo, socket, std::path::PathBuf::from("/dev/null")] {
        let error = KnownHosts::new(path.clone(), None)
            .lookup("h", 22)
            .unwrap_err();
        assert_eq!(error.path, path);
        assert_eq!(error.source.kind(), io::ErrorKind::PermissionDenied);
    }
    let error = KnownHosts::new(dir.path().to_owned(), None)
        .lookup("h", 22)
        .unwrap_err();
    assert_eq!(error.source.raw_os_error(), Some(libc::EISDIR));
}

#[test]
fn ssh_host_authority_public_aliases_missing_and_raw_routes() {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    const CHILD: &str = "QSH_SSH_AUTHORITY_RELATIVE_CHILD";
    if let Some(mode) = std::env::var_os(CHILD) {
        if mode == "wait-error" {
            use std::io::Read;
            let mut byte = [0];
            std::io::stdin().read_exact(&mut byte).unwrap();
            assert_eq!(byte, *b"x");
        }
        let keys = KnownHosts::new("./known_hosts".into(), None)
            .lookup("h", 22)
            .unwrap();
        assert_eq!(keys.known, vec![K1.to_vec()]);
        let receipt = if mode == "wait-error" {
            "wait-receipt"
        } else {
            "relative-receipt"
        };
        std::fs::write(receipt, b"actual relative lookup completed\n").unwrap();
        return;
    }
    let dir = authority_dir();
    let base = dir.path().canonicalize().unwrap();
    let path = base.join("known_hosts");
    authority_file(&path, line("h", K1));
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap();
    let hard = base.join("hardlink");
    std::fs::hard_link(&path, &hard).unwrap();
    let alias = base.join("alias");
    symlink("known_hosts", &alias).unwrap();
    let parent_alias = base.join("parent-alias");
    symlink(&base, &parent_alias).unwrap();
    let before = std::fs::metadata(&path).unwrap();
    for route in [&path, &hard, &alias, &parent_alias.join("alias")] {
        assert_eq!(
            KnownHosts::new(route.to_owned(), None)
                .lookup("h", 22)
                .unwrap()
                .known,
            vec![K1.to_vec()]
        );
    }
    let after = std::fs::metadata(&path).unwrap();
    assert_eq!(
        (before.dev(), before.ino(), before.mode(), before.nlink()),
        (after.dev(), after.ino(), after.mode(), after.nlink())
    );

    let child_dir = base.join("physical");
    let nested = child_dir.join("nested");
    std::fs::create_dir(&child_dir).unwrap();
    std::fs::create_dir(&nested).unwrap();
    for p in [&child_dir, &nested] {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    authority_file(&child_dir.join("known_hosts"), line("h", K2));
    symlink("physical/nested", base.join("jump")).unwrap();
    assert_eq!(
        KnownHosts::new(base.join("jump/../known_hosts"), None)
            .lookup("h", 22)
            .unwrap()
            .known,
        vec![K2.to_vec()]
    );
    for suffix in [
        "known_hosts/",
        "known_hosts/.",
        "known_hosts/../known_hosts",
    ] {
        let error = KnownHosts::new(base.join(suffix), None)
            .lookup("h", 22)
            .unwrap_err();
        assert_eq!(error.source.raw_os_error(), Some(libc::ENOTDIR));
    }
    symlink("missing", base.join("dangling")).unwrap();
    assert!(KnownHosts::new(base.join("dangling"), None)
        .lookup("h", 22)
        .is_err());
    for i in (0..40).rev() {
        let target = if i == 39 {
            "known_hosts".to_owned()
        } else {
            format!("alias-{}", i + 1)
        };
        symlink(target, base.join(format!("alias-{i}"))).unwrap();
    }
    assert_eq!(
        KnownHosts::new(base.join("alias-0"), None)
            .lookup("h", 22)
            .unwrap()
            .known,
        vec![K1.to_vec()]
    );
    symlink("alias-0", base.join("alias-41")).unwrap();
    assert_eq!(
        KnownHosts::new(base.join("alias-41"), None)
            .lookup("h", 22)
            .unwrap_err()
            .source
            .raw_os_error(),
        Some(libc::ELOOP)
    );

    let raw = std::ffi::OsString::from_vec(b"raw-\xff".to_vec());
    assert_eq!(
        super::storage::parts(raw.as_bytes(), false)
            .pop_front()
            .unwrap()
            .0
            .as_bytes(),
        raw.as_bytes()
    );
    let raw_path = base.join(raw);
    match std::fs::write(&raw_path, line("h", K1)) {
        Ok(()) => {
            std::fs::set_permissions(&raw_path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert_eq!(
                KnownHosts::new(raw_path, None)
                    .lookup("h", 22)
                    .unwrap()
                    .known,
                vec![K1.to_vec()]
            );
        }
        Err(error) => {
            assert_eq!(error.raw_os_error(), Some(libc::EILSEQ));
            // Lookup can refuse differently from creation (for example ENOENT
            // on a rejecting filesystem); compare the corresponding lookup.
            let reference = std::fs::symlink_metadata(&raw_path).unwrap_err();
            let lookup = KnownHosts::new(raw_path, None).lookup("h", 22);
            if reference.kind() == io::ErrorKind::NotFound {
                assert_eq!(lookup.unwrap(), HostKeys::default());
            } else {
                assert_eq!(
                    lookup.unwrap_err().source.raw_os_error(),
                    reference.raw_os_error()
                );
            }
        }
    }

    let search = base.join("search");
    std::fs::create_dir(&search).unwrap();
    authority_file(&search.join("known_hosts"), line("h", K1));
    std::fs::set_permissions(&search, std::fs::Permissions::from_mode(0o111)).unwrap();
    let result = KnownHosts::new(search.join("known_hosts"), None).lookup("h", 22);
    std::fs::set_permissions(&search, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(result.unwrap().known, vec![K1.to_vec()]);
    let sticky = base.join("sticky");
    std::fs::create_dir(&sticky).unwrap();
    std::fs::set_permissions(&sticky, std::fs::Permissions::from_mode(0o1777)).unwrap();
    authority_file(&sticky.join("known_hosts"), line("h", K1));
    assert_eq!(
        KnownHosts::new(sticky.join("known_hosts"), None)
            .lookup("h", 22)
            .unwrap()
            .known,
        vec![K1.to_vec()]
    );

    let mut child = AuthorityChild::new(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "known_hosts::tests::ssh_host_authority_public_aliases_missing_and_raw_routes",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .current_dir(&base)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.poll().unwrap() {
            break status;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "owned relative child exceeded deadline"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    };
    assert!(status.success());
    assert_eq!(
        std::fs::read(base.join("relative-receipt")).unwrap(),
        b"actual relative lookup completed\n"
    );

    // Inject the result-poll error while an actual owned child waits for input.
    // Cleanup must retain that observation, not kill before the next poll can
    // release it. Successful child exit and its real lookup receipt prove this.
    let mut guarded = AuthorityChild::new(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "known_hosts::tests::ssh_host_authority_public_aliases_missing_and_raw_routes",
                "--nocapture",
            ])
            .env(CHILD, "wait-error")
            .current_dir(&base)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut input = guarded.child.stdin.take();
    let error = guarded
        .poll_with(|_| Err(io::Error::from_raw_os_error(libc::ECHILD)))
        .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::ECHILD));
    let mut polls = 0;
    let status = guarded.finish_with(|child| {
        polls += 1;
        if polls == 2 {
            if let Some(mut pipe) = input.take() {
                let _ = pipe.write_all(b"x");
            }
        }
        child.try_wait()
    });
    assert!(polls >= 2);
    assert!(
        status.success(),
        "cleanup killed the owned child after result-poll ECHILD: {status}"
    );
    assert_eq!(
        std::fs::read(base.join("wait-receipt")).unwrap(),
        b"actual relative lookup completed\n"
    );
}

// Keep the exact owned child alive through wait errors/unwind. ECHILD is not
// completion evidence and must never trigger a numeric-PID kill.
struct AuthorityChild {
    child: std::process::Child,
    lost_wait: bool,
}
impl AuthorityChild {
    fn new(child: std::process::Child) -> Self {
        Self {
            child,
            lost_wait: false,
        }
    }
    fn poll(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
        self.poll_with(|child| child.try_wait())
    }
    fn poll_with(
        &mut self,
        wait: impl FnOnce(&mut std::process::Child) -> io::Result<Option<std::process::ExitStatus>>,
    ) -> io::Result<Option<std::process::ExitStatus>> {
        let result = wait(&mut self.child);
        if let Err(error) = &result {
            self.lost_wait |= error.raw_os_error() == Some(libc::ECHILD);
        }
        result
    }
    fn finish_with(
        &mut self,
        mut wait: impl FnMut(&mut std::process::Child) -> io::Result<Option<std::process::ExitStatus>>,
    ) -> std::process::ExitStatus {
        let mut killed = false;
        let mut reported = false;
        loop {
            match self.poll_with(&mut wait) {
                Ok(Some(status)) => return status,
                Err(error) => {
                    if !reported {
                        eprintln!("owned relative fixture wait failed: {error}");
                        reported = true;
                    }
                    if !self.lost_wait && !killed {
                        let _ = self.child.kill();
                        killed = true;
                    }
                }
                Ok(None) if !self.lost_wait && !killed => {
                    let _ = self.child.kill();
                    killed = true;
                }
                Ok(None) => {}
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
}
impl Drop for AuthorityChild {
    fn drop(&mut self) {
        self.finish_with(|child| child.try_wait());
    }
}

#[test]
fn ssh_host_authority_complete_reads_preserve_parser_and_bindings() {
    use std::io::Read;
    let dir = authority_dir();
    let user = dir.path().join("user");
    let system = dir.path().join("system");
    let prefix = line("h", K1);
    assert!(parse_line(&prefix).is_some());
    authority_file(&user, &prefix);
    let mut consumed = false;
    let error = super::storage::read_with(&user, |file| {
        let mut bytes = vec![0; prefix.len()];
        file.read_exact(&mut bytes)?;
        assert_eq!(bytes, prefix.as_bytes());
        consumed = true;
        Err(io::Error::from_raw_os_error(libc::EIO))
    })
    .err()
    .expect("I/O error after a complete parseable prefix must not produce a snapshot");
    assert!(consumed);
    assert_eq!(error.raw_os_error(), Some(libc::EIO));
    let bytes = [
        prefix.as_bytes(),
        b"invalid-\xff\n",
        format!("@revoked {}", line("h", K2)).as_bytes(),
    ]
    .concat();
    authority_file(&user, bytes);
    let keys = KnownHosts::new(user.clone(), None).lookup("h", 22).unwrap();
    assert_eq!(keys.known, vec![K1.to_vec()]);
    assert_eq!(keys.revoked, vec![K2.to_vec()]);

    for second_store in [false, true] {
        authority_file(&user, &prefix);
        authority_file(&system, line("h", K2));
        let replacement = dir.path().join("replacement");
        authority_file(&replacement, line("sentinel", K2));
        let sentinel = std::fs::read(&replacement).unwrap();
        let mut fired = false;
        let stores = KnownHosts::new(user.clone(), second_store.then_some(system.clone()));
        let result = stores.lookup_with("h", 22, |path| {
            let snapshot = super::storage::read(path)?;
            if (second_store && path == system) || (!second_store && path == user) {
                std::fs::rename(&replacement, &user)?;
                fired = true;
            }
            Ok(snapshot)
        });
        assert!(fired);
        let error = result.unwrap_err();
        assert_eq!(error.path, user);
        assert_eq!(error.source.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(std::fs::read(&user).unwrap(), sentinel);
    }
    authority_file(&user, &prefix);
    let stores = KnownHosts::new(user.clone(), Some(system.clone()));
    let error = stores
        .lookup_with("h", 22, |path| {
            let snapshot = super::storage::read(path)?;
            if path == system {
                std::fs::remove_file(&user)?;
            }
            Ok(snapshot)
        })
        .unwrap_err();
    assert_eq!(error.path, user);
    assert_eq!(error.source.kind(), io::ErrorKind::NotFound);

    // Retain exact absence evidence too: an initially missing user prefix
    // cannot be populated while the second store is read and still be empty.
    let absent = dir.path().join("missing/known_hosts");
    let stores = KnownHosts::new(absent.clone(), Some(system.clone()));
    let error = stores
        .lookup_with("h", 22, |path| {
            let snapshot = super::storage::read(path)?;
            if path == system {
                std::fs::create_dir(absent.parent().unwrap())?;
                authority_file(&absent, line("h", K1));
            }
            Ok(snapshot)
        })
        .unwrap_err();
    assert_eq!(error.path, absent);
    assert_eq!(error.source.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(std::fs::read(&absent).unwrap(), line("h", K1).as_bytes());

    authority_file(&user, &prefix);
    let stores = KnownHosts::new(user.clone(), Some(system.clone()));
    let error = stores
        .lookup_with("h", 22, |path| {
            use std::os::unix::fs::PermissionsExt;
            let snapshot = super::storage::read(path)?;
            if path == system {
                std::fs::set_permissions(&user, std::fs::Permissions::from_mode(0o666))?;
            }
            Ok(snapshot)
        })
        .unwrap_err();
    assert_eq!(error.path, user);
    assert_eq!(error.source.kind(), io::ErrorKind::PermissionDenied);
}

#[test]
fn ssh_host_authority_append_preserves_target_alias_hardlink_and_modes() {
    use std::os::unix::fs::{symlink, MetadataExt};
    for initial in [b"".as_slice(), b"no newline", b"already\n", b"bad-\xff"] {
        for route in ["target", "alias", "hardlink"] {
            let dir = authority_dir();
            let target = dir.path().join("target");
            authority_file(&target, initial);
            let alias = dir.path().join("alias");
            symlink("target", &alias).unwrap();
            let hard = dir.path().join("hardlink");
            std::fs::hard_link(&target, &hard).unwrap();
            let before = std::fs::metadata(&target).unwrap();
            KnownHosts::new(dir.path().join(route), None)
                .add("new.example", 2222, "ssh-ed25519", K1)
                .unwrap();
            let mut expected = initial.to_vec();
            if initial.last().is_some_and(|last| *last != b'\n') {
                expected.push(b'\n');
            }
            expected.extend_from_slice(line("[new.example]:2222", K1).as_bytes());
            for path in [&target, &alias, &hard] {
                assert_eq!(std::fs::read(path).unwrap(), expected);
                let after = std::fs::metadata(path).unwrap();
                assert_eq!(
                    (before.dev(), before.ino(), before.mode(), before.nlink()),
                    (after.dev(), after.ino(), after.mode(), after.nlink())
                );
            }
            assert!(std::fs::symlink_metadata(&alias)
                .unwrap()
                .file_type()
                .is_symlink());
        }
    }
}

#[test]
fn ssh_host_authority_append_tail_and_write_share_one_object() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    for replacement in ["leaf", "alias", "parent", "mode"] {
        let dir = authority_dir();
        let parent = dir.path().join("parent");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        let source = parent.join("known_hosts");
        let original = b"# original, no newline";
        authority_file(&source, original);
        let held_name = dir.path().join("original-hardlink");
        std::fs::hard_link(&source, &held_name).unwrap();
        let sentinel = dir.path().join("sentinel");
        authority_file(&sentinel, b"# replacement sentinel\n");
        let configured = if replacement == "alias" {
            let alias = parent.join("alias");
            symlink("known_hosts", &alias).unwrap();
            alias
        } else {
            source.clone()
        };
        let mut fired = false;
        let result = KnownHosts::new(configured.clone(), None).add_with(
            "new.example",
            22,
            "ssh-ed25519",
            K1,
            super::storage::read_tail,
            || {
                match replacement {
                    "leaf" => std::fs::rename(&sentinel, &configured)?,
                    "alias" => {
                        std::fs::remove_file(&configured)?;
                        symlink(&sentinel, &configured)?;
                    }
                    "mode" => {
                        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o666))?
                    }
                    "parent" => {
                        std::fs::rename(&parent, dir.path().join("displaced"))?;
                        std::fs::create_dir(&parent)?;
                        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755))?;
                        std::fs::rename(&sentinel, &source)?;
                    }
                    _ => unreachable!(),
                }
                fired = true;
                Ok(())
            },
        );
        assert!(fired);
        let replacement_path = if replacement == "alias" {
            &sentinel
        } else {
            &source
        };
        assert_eq!(
            std::fs::read(replacement_path).unwrap(),
            if replacement == "mode" {
                original.as_slice()
            } else {
                b"# replacement sentinel\n"
            },
            "replacement {replacement} must not be appended"
        );
        assert_eq!(std::fs::read(&held_name).unwrap(), original);
        assert!(
            result.is_err(),
            "observed {replacement} replacement must refuse"
        );
    }
}

#[test]
fn ssh_host_authority_append_read_errors_are_not_ignored() {
    use std::io::Read;
    let dir = authority_dir();
    let path = dir.path().join("known_hosts");
    let prefix = line("h", K1);
    assert!(parse_line(&prefix).is_some());
    authority_file(&path, &prefix);
    let mut consumed = false;
    let result = KnownHosts::new(path.clone(), None).add_with(
        "new.example",
        22,
        "ssh-ed25519",
        K2,
        |file| {
            let mut bytes = vec![0; prefix.len()];
            file.read_exact(&mut bytes)?;
            assert_eq!(bytes, prefix.as_bytes());
            consumed = true;
            Err(io::Error::from_raw_os_error(libc::EIO))
        },
        || Ok(()),
    );
    assert!(consumed);
    assert_eq!(
        std::fs::read(&path).unwrap(),
        prefix.as_bytes(),
        "tail read failure must not append after a valid prefix"
    );
    assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EIO));
}

#[test]
fn ssh_host_authority_creation_is_exclusive_and_never_repairs() {
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    let dir = authority_dir();
    let path = dir.path().join("new/ssh/known_hosts");
    KnownHosts::new(path.clone(), None)
        .add("h", 22, "ssh-ed25519", K1)
        .unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    for parent in [
        path.parent().unwrap(),
        path.parent().unwrap().parent().unwrap(),
    ] {
        assert_eq!(std::fs::metadata(parent).unwrap().mode() & 0o777, 0o700);
    }
    let parent_alias = dir.path().join("parent-alias");
    symlink(path.parent().unwrap(), &parent_alias).unwrap();
    let aliased_new = parent_alias.join("another");
    KnownHosts::new(aliased_new.clone(), None)
        .add("h", 22, "ssh-ed25519", K2)
        .unwrap();
    assert_eq!(
        KnownHosts::new(aliased_new, None)
            .lookup("h", 22)
            .unwrap()
            .known,
        vec![K2.to_vec()]
    );

    let dangling = dir.path().join("dangling");
    let absent = dir.path().join("must-stay-missing");
    symlink(&absent, &dangling).unwrap();
    let before = std::fs::symlink_metadata(&dangling).unwrap();
    assert!(KnownHosts::new(dangling.clone(), None)
        .add("h", 22, "ssh-ed25519", K1)
        .is_err());
    assert!(!absent.exists());
    assert!(std::fs::symlink_metadata(&dangling)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(
        std::fs::symlink_metadata(&dangling).unwrap().ino(),
        before.ino()
    );

    for unsafe_parent in [false, true] {
        let parent = dir.path().join(format!("unsafe-{unsafe_parent}"));
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(
            &parent,
            std::fs::Permissions::from_mode(if unsafe_parent { 0o777 } else { 0o755 }),
        )
        .unwrap();
        let file = parent.join("known_hosts");
        authority_file(&file, b"# unsafe unchanged\n");
        if !unsafe_parent {
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
        }
        let held = std::fs::metadata(&file).unwrap();
        let parent_before = std::fs::metadata(&parent).unwrap();
        assert!(KnownHosts::new(file.clone(), None)
            .add("h", 22, "ssh-ed25519", K1)
            .is_err());
        let after = std::fs::metadata(&file).unwrap();
        assert_eq!(
            (held.dev(), held.ino(), held.mode()),
            (after.dev(), after.ino(), after.mode())
        );
        assert_eq!(
            std::fs::metadata(&parent).unwrap().mode(),
            parent_before.mode()
        );
        assert_eq!(std::fs::read(&file).unwrap(), b"# unsafe unchanged\n");
    }

    let exclusive = dir.path().join("exclusive");
    let mut fired = false;
    let mut planted = None;
    let error = super::storage::AppendFile::open_with(&exclusive, || {
        authority_file(&exclusive, b"# exclusive sentinel\n");
        planted = Some(std::fs::metadata(&exclusive)?);
        fired = true;
        Ok(())
    })
    .err()
    .expect("EXCL must reject the appeared entry");
    assert!(fired);
    assert_eq!(error.raw_os_error(), Some(libc::EEXIST));
    let before = planted.unwrap();
    let after = std::fs::metadata(&exclusive).unwrap();
    assert_eq!(
        (before.dev(), before.ino(), before.mode()),
        (after.dev(), after.ino(), after.mode())
    );
    assert_eq!(
        std::fs::read(&exclusive).unwrap(),
        b"# exclusive sentinel\n"
    );

    let parent = dir.path().join("create-parent");
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
    let file = parent.join("known_hosts");
    let displaced = dir.path().join("create-displaced");
    let error = super::storage::AppendFile::open_with(&file, || {
        std::fs::rename(&parent, &displaced)?;
        std::fs::create_dir(&parent)?;
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755))?;
        Ok(())
    })
    .err()
    .expect("route replacement before create must refuse");
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(!file.exists());
    assert!(!displaced.join("known_hosts").exists());

    // A failure after exclusive creation preserves the new owned data entry;
    // there is no unlink/truncate/permission-repair rollback path.
    let failed = dir.path().join("created-before-read-error");
    let error = KnownHosts::new(failed.clone(), None)
        .add_with(
            "h",
            22,
            "ssh-ed25519",
            K1,
            |_| Err(io::Error::from_raw_os_error(libc::EIO)),
            || Ok(()),
        )
        .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::EIO));
    assert!(std::fs::metadata(&failed).unwrap().is_file());
    assert_eq!(std::fs::metadata(&failed).unwrap().mode() & 0o777, 0o600);
    assert_eq!(std::fs::read(&failed).unwrap(), b"");
}
