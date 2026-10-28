use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};

fn private_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    root
}
fn request() -> bringup::ImageRequest {
    bringup::ImageRequest {
        version: "0.4.0".into(),
        platform: bringup::Platform::from_uname("Linux", "x86_64").unwrap(),
    }
}

#[test]
fn cache_authority_lock_policy_and_binding_are_checked() {
    // Synthetic owner-policy rows; actual foreign-UID qualification is the root CI fixture.
    for (owner, accepted) in [(0, true), (42, true), (43, false)] {
        assert_eq!(trusted_owner(owner, 42), accepted);
    }
    let root = private_root();
    let cancel = knock::Cancel::new();
    let budget = Budget::new(Duration::from_secs(5), &cancel);
    let authority = Authority::open(root.path(), &request(), &budget)
        .ok()
        .unwrap();
    let target = root.path().join("releases/0.4.0/x86_64-unknown-linux-musl");
    let lock = target.join(".lock");
    let original = std::fs::metadata(&lock).unwrap();
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(authority.validate(&budget).is_err());
    drop(authority);
    assert!(Authority::open(root.path(), &request(), &budget).is_err());
    assert_eq!(std::fs::metadata(&lock).unwrap().mode() & 0o777, 0o644);
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o600)).unwrap();
    let extra = target.join("lock-link");
    std::fs::hard_link(&lock, &extra).unwrap();
    assert!(Authority::open(root.path(), &request(), &budget).is_err());
    std::fs::remove_file(extra).unwrap();
    let authority = Authority::open(root.path(), &request(), &budget)
        .ok()
        .unwrap();
    std::fs::rename(&lock, target.join("old-lock")).unwrap();
    std::fs::write(&lock, b"replacement").unwrap();
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        authority.validate(&budget).is_err(),
        "never acquire the replacement lock"
    );
    assert!(same(&original, &authority.lock.metadata().unwrap()));
    assert_eq!(std::fs::read(lock).unwrap(), b"replacement");
}

#[test]
fn cache_authority_reads_are_bounded_and_nonfollowing() {
    // Socket addresses have a smaller bound than ordinary cache paths. Keep
    // the owned bind root short even when the host TMPDIR is long.
    let root = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in("/tmp")
        .unwrap();
    let cache_root = root.path().join("cache-".to_owned() + &"x".repeat(128));
    let cancel = knock::Cancel::new();
    let budget = Budget::new(Duration::from_secs(5), &cancel);
    let authority = Authority::open(&cache_root, &request(), &budget)
        .ok()
        .unwrap();
    let target = cache_root.join("releases/0.4.0/x86_64-unknown-linux-musl");
    let path = target.join("data");
    std::fs::write(&path, b"public").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::hard_link(&path, target.join("extra-link")).unwrap();
    assert!(std::fs::metadata(&path).unwrap().nlink() > 1);
    let read = authority.target.read("data", 6, &budget).ok().unwrap();
    assert_eq!(read.bytes, b"public");
    assert!(authority.target.read("data", 5, &budget).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(read.validate().is_err());
    assert!(authority.target.read("data", 6, &budget).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    symlink(&path, target.join("alias")).unwrap();
    assert!(authority.target.read("alias", 6, &budget).is_err());
    std::fs::create_dir(target.join("directory")).unwrap();
    assert!(authority.target.read("directory", 6, &budget).is_err());
    use std::os::unix::fs::FileTypeExt;
    let deep_socket = target.join("socket");
    assert!(deep_socket.as_os_str().len() > 128);
    let short_socket = root.path().join("s");
    let socket = std::os::unix::net::UnixListener::bind(&short_socket).unwrap();
    let before = std::fs::symlink_metadata(&short_socket).unwrap();
    assert!(before.file_type().is_socket());
    // Both names are under the same owned root, so rename preserves the real
    // socket inode without encoding the long cache path as a socket address.
    std::fs::rename(&short_socket, &deep_socket).unwrap();
    let after = std::fs::symlink_metadata(&deep_socket).unwrap();
    assert!(after.file_type().is_socket());
    assert!(same(&before, &after));
    assert!(authority.target.read("socket", 6, &budget).is_err());
    assert!(
        socket.local_addr().is_ok(),
        "the renamed socket remains owned and live"
    );
    nix::unistd::mkfifo(
        &target.join("fifo"),
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();
    assert!(authority.target.read("fifo", 6, &budget).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"public");

    // The metadata snapshot can precede growth; bound actual read requests too.
    struct Growing {
        file: File,
        path: PathBuf,
        grew: bool,
        requests: Vec<usize>,
    }
    impl Read for Growing {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.requests.push(buffer.len());
            let count = self.file.read(buffer)?;
            if !self.grew {
                use std::io::Write;
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(&self.path)?
                    .write_all(b"cdefg")?;
                self.grew = true;
            }
            Ok(count)
        }
    }
    let growth_path = target.join("growth");
    std::fs::write(&growth_path, b"ab").unwrap();
    let file = File::open(&growth_path).unwrap();
    assert_eq!(file.metadata().unwrap().len(), 2);
    let mut growing = Growing {
        file,
        path: growth_path,
        grew: false,
        requests: vec![],
    };
    assert!(complete_read(&mut growing, 6, &budget).is_err());
    assert!(
        growing.requests.iter().all(|&request| request <= 7),
        "actual limit+1 reads: {:?}",
        growing.requests
    );

    struct FailsAfterPrefix(bool);
    impl Read for FailsAfterPrefix {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.0 {
                return Err(io::Error::other("owned injected read error after prefix"));
            }
            self.0 = true;
            buffer[0] = b'x';
            Ok(1)
        }
    }
    assert!(complete_read(&mut FailsAfterPrefix(false), 6, &budget).is_err());
}

#[test]
fn cache_authority_root_walk_preserves_raw_search_and_alias_bounds() {
    let root = private_root();
    let physical = std::fs::canonicalize(root.path()).unwrap();
    let cancel = knock::Cancel::new();
    let budget = Budget::new(Duration::from_secs(5), &cancel);
    let actual = physical.join("actual");
    std::fs::create_dir(&actual).unwrap();
    std::fs::set_permissions(&actual, std::fs::Permissions::from_mode(0o755)).unwrap();
    for number in (0..41).rev() {
        let target = if number == 40 {
            PathBuf::from("actual")
        } else {
            PathBuf::from(format!("a{}", number + 1))
        };
        symlink(target, physical.join(format!("a{number}"))).unwrap();
    }
    assert!(
        walk(&physical.join("a1"), false, &budget).is_ok(),
        "40 owned aliases"
    );
    assert!(
        walk(&physical.join("a0"), false, &budget).is_err(),
        "41 owned aliases"
    );
    let searchable = physical.join("search");
    std::fs::create_dir(&searchable).unwrap();
    std::fs::create_dir(searchable.join("cache")).unwrap();
    std::fs::set_permissions(
        searchable.join("cache"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    std::fs::set_permissions(&searchable, std::fs::Permissions::from_mode(0o111)).unwrap();
    assert!(walk(&searchable.join("cache"), false, &budget).is_ok());
    assert_eq!(
        std::fs::metadata(&searchable).unwrap().mode() & 0o777,
        0o111
    );
    std::fs::set_permissions(&searchable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let raw = physical.join(OsString::from_vec(b"raw-\xff".to_vec()));
    match std::fs::create_dir(&raw) {
        Ok(()) => {
            std::fs::set_permissions(&raw, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert!(walk(&raw, false, &budget).is_ok());
        }
        Err(error) => {
            assert_eq!(error.raw_os_error(), Some(libc::EILSEQ));
            assert!(
                walk(&raw, false, &budget).is_err(),
                "perform the real raw lookup even on a rejecting filesystem"
            );
        }
    }
    symlink("actual", physical.join("short")).unwrap();
    assert!(walk(&physical.join("short/../actual"), false, &budget).is_ok());
}

fn fixture_archive(body: &[u8], budget: &Budget<'_>) -> (Vec<u8>, [u8; 32], bringup::DaemonImage) {
    use std::io::Write;
    let mut tar = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_ustar();
    header.set_size(body.len() as u64);
    header.set_mode(0o755);
    header.set_cksum();
    tar.append_data(
        &mut header,
        "qsh-0.4.0-x86_64-unknown-linux-musl/qshd",
        body,
    )
    .unwrap();
    let tar = tar.into_inner().unwrap();
    let mut zip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    zip.write_all(&tar).unwrap();
    let bytes = zip.finish().unwrap();
    let sha = super::super::archive::hash(&bytes, budget).unwrap();
    let image = super::super::archive::verified_image(&request(), &bytes, &sha, budget).unwrap();
    (bytes, sha, image)
}

#[test]
fn cache_authority_substitution_refuses_read_and_mutation() {
    use super::super::{Cache, Phase};
    for boundary in [0, 1, 2] {
        let owner = private_root();
        let root = owner.path().join("cache");
        let cancel = knock::Cancel::new();
        let budget = Budget::new(Duration::from_secs(5), &cancel);
        let (bytes, sha, image) = fixture_archive(b"original", &budget);
        let cache = Cache::open(&root, &request(), &budget).ok().unwrap();
        cache
            .publish(&request(), &bytes, &sha, &image, &budget)
            .ok()
            .unwrap();
        let generation = root
            .join("releases/0.4.0/x86_64-unknown-linux-musl/objects")
            .join(super::super::archive::hex(&sha));
        std::fs::set_permissions(&generation, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_file(generation.join("image")).unwrap();
        let kept = owner.path().join("retained-generation");
        let target = generation.clone();
        let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = fired.clone();
        *cache.hook.borrow_mut() = Some(Box::new(move |phase| {
            let selected = matches!(
                (boundary, phase),
                (0, Phase::AfterImageRead)
                    | (1, Phase::BeforeRepair)
                    | (2, Phase::BeforeGenerationRename(_))
            );
            if selected && !flag.swap(true, std::sync::atomic::Ordering::SeqCst) {
                std::fs::rename(&target, &kept).unwrap();
                std::fs::create_dir(&target).unwrap();
                std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
                std::fs::write(target.join("image"), b"replacement sentinel").unwrap();
            }
        }));
        if boundary < 2 {
            assert!(cache
                .load(&request(), None, &budget, Duration::from_secs(5))
                .unwrap()
                .is_none());
        } else {
            assert!(cache
                .publish(&request(), &bytes, &sha, &image, &budget)
                .is_err());
        }
        assert!(fired.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(
            std::fs::read(generation.join("image")).unwrap(),
            b"replacement sentinel",
            "boundary {boundary}"
        );
    }
    // Required root/lock substitution is distinct from an optional image error.
    for replace_root in [true, false] {
        let owner = private_root();
        let root = owner.path().join("cache");
        let cancel = knock::Cancel::new();
        let budget = Budget::new(Duration::from_secs(5), &cancel);
        let (bytes, sha, image) = fixture_archive(b"required authority", &budget);
        let cache = Cache::open(&root, &request(), &budget).ok().unwrap();
        cache
            .publish(&request(), &bytes, &sha, &image, &budget)
            .ok()
            .unwrap();
        let target = root.join("releases/0.4.0/x86_64-unknown-linux-musl");
        let protected = if replace_root {
            let other = owner.path().join("other");
            let replacement = Cache::open(&other, &request(), &budget).ok().unwrap();
            replacement
                .publish(&request(), &bytes, &sha, &image, &budget)
                .ok()
                .unwrap();
            drop(replacement);
            std::fs::rename(&root, owner.path().join("retained-root")).unwrap();
            std::fs::rename(&other, &root).unwrap();
            target.join("current.json")
        } else {
            let lock = target.join(".lock");
            std::fs::rename(&lock, target.join("retained-lock")).unwrap();
            std::fs::write(&lock, b"unrelated lock").unwrap();
            std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o600)).unwrap();
            lock
        };
        let original = std::fs::read(&protected).unwrap();
        assert!(cache
            .load(&request(), None, &budget, Duration::from_secs(5))
            .unwrap()
            .is_none());
        assert!(cache
            .publish(&request(), &bytes, &sha, &image, &budget)
            .is_err());
        assert_eq!(std::fs::read(protected).unwrap(), original);
    }
    let root = private_root();
    let cancel = knock::Cancel::new();
    let budget = Budget::new(Duration::from_secs(5), &cancel);
    let (bytes, sha, image) =
        fixture_archive(b"verified archive survives optional image refusal", &budget);
    let cache = Cache::open(root.path(), &request(), &budget).ok().unwrap();
    cache
        .publish(&request(), &bytes, &sha, &image, &budget)
        .ok()
        .unwrap();
    let generation = root
        .path()
        .join("releases/0.4.0/x86_64-unknown-linux-musl/objects")
        .join(super::super::archive::hex(&sha));
    let sentinel = root.path().join("outside-image");
    std::fs::write(&sentinel, b"untouched optional image").unwrap();
    std::fs::remove_file(generation.join("image")).unwrap();
    symlink(&sentinel, generation.join("image")).unwrap();
    let recovered = cache
        .load(&request(), None, &budget, Duration::from_secs(5))
        .unwrap()
        .unwrap();
    assert_eq!(recovered.bytes, image.bytes);
    assert!(std::fs::symlink_metadata(generation.join("image"))
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(
        std::fs::read(sentinel).unwrap(),
        b"untouched optional image"
    );
}

#[test]
fn cache_authority_publication_keeps_one_lock_and_pointer_last() {
    use super::super::{Cache, Phase};
    let root = private_root();
    let cancel = knock::Cancel::new();
    let budget = Budget::new(Duration::from_secs(5), &cancel);
    let cache = Cache::open(root.path(), &request(), &budget).ok().unwrap();
    let (old, old_sha, old_image) = fixture_archive(b"old", &budget);
    cache
        .publish(&request(), &old, &old_sha, &old_image, &budget)
        .ok()
        .unwrap();
    let target = root.path().join("releases/0.4.0/x86_64-unknown-linux-musl");
    let pointer = target.join("current.json");
    let old_pointer = std::fs::read(&pointer).unwrap();
    let lock = File::open(target.join(".lock")).unwrap();
    let lock_identity = lock.metadata().unwrap();
    assert_eq!(
        fs::flock(&lock, FlockOperation::NonBlockingLockExclusive),
        Err(rustix::io::Errno::WOULDBLOCK)
    );
    let (new, sha, image) = fixture_archive(b"new", &budget);
    let generation = target
        .join("objects")
        .join(super::super::archive::hex(&sha));
    let recorded = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = recorded.clone();
    let expected = old_pointer.clone();
    let current = pointer.clone();
    let complete = generation.clone();
    *cache.hook.borrow_mut() = Some(Box::new(move |phase| {
        if matches!(phase, Phase::BeforePointerRename) {
            assert_eq!(std::fs::read(&current).unwrap(), expected);
            for file in ["archive", "image", "receipt.json"] {
                assert!(complete.join(file).is_file());
            }
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            std::fs::rename(&current, current.with_extension("old")).unwrap();
            std::fs::create_dir(&current).unwrap();
        }
    }));
    assert!(cache
        .publish(&request(), &new, &sha, &image, &budget)
        .is_err());
    assert!(recorded.load(std::sync::atomic::Ordering::SeqCst));
    assert!(pointer.is_dir());
    assert!(
        generation.join("archive").is_file(),
        "completed unreferenced generation survives pointer failure"
    );
    assert!(same(
        &lock_identity,
        &std::fs::metadata(target.join(".lock")).unwrap()
    ));
    for existing in [false, true] {
        for before_pointer in [false, true] {
            let owner = private_root();
            let root = owner.path().join("cache");
            let cache = Cache::open(&root, &request(), &budget).ok().unwrap();
            cache
                .publish(&request(), &old, &old_sha, &old_image, &budget)
                .ok()
                .unwrap();
            let target = root.join("releases/0.4.0/x86_64-unknown-linux-musl");
            let pointer = target.join("current.json");
            let pointer_before = std::fs::read(&pointer).unwrap();
            let pointer_identity = std::fs::metadata(&pointer).unwrap();
            let (bytes, digest, expected_image) = if existing {
                (&old, &old_sha, &old_image)
            } else {
                (&new, &sha, &image)
            };
            let generation = target
                .join("objects")
                .join(super::super::archive::hex(digest));
            let retained = owner.path().join("retained-complete-generation");
            let original = retained.clone();
            let replacement = generation.clone();
            let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let flag = fired.clone();
            *cache.hook.borrow_mut() = Some(Box::new(move |phase| {
                let selected = if before_pointer {
                    matches!(phase, Phase::BeforePointerRename)
                } else {
                    matches!(phase, Phase::AfterGenerationCommit)
                };
                if selected && !flag.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    std::fs::rename(&replacement, &original).unwrap();
                    std::fs::create_dir(&replacement).unwrap();
                    std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o700))
                        .unwrap();
                    std::fs::write(replacement.join("sentinel"), b"replacement generation")
                        .unwrap();
                }
            }));
            let result = cache.publish(&request(), bytes, digest, expected_image, &budget);
            assert!(fired.load(std::sync::atomic::Ordering::SeqCst));
            assert!(result.is_err(), "replacement after generation commit must refuse pointer publication: existing={existing}, before_pointer={before_pointer}");
            assert_eq!(std::fs::read(&pointer).unwrap(), pointer_before);
            assert!(same(
                &pointer_identity,
                &std::fs::metadata(&pointer).unwrap()
            ));
            assert_eq!(
                std::fs::read(generation.join("sentinel")).unwrap(),
                b"replacement generation"
            );
            for name in ["archive", "image", "receipt.json"] {
                assert!(retained.join(name).is_file());
            }
        }
    }
}

#[test]
fn cache_authority_cleanup_never_removes_replacements() {
    use super::super::{Cache, Phase};
    let root = private_root();
    let cancel = knock::Cancel::new();
    let budget = Budget::new(Duration::from_secs(5), &cancel);
    let cache = Cache::open(root.path(), &request(), &budget).ok().unwrap();
    let (bytes, sha, image) = fixture_archive(b"owned stage", &budget);
    let objects = root
        .path()
        .join("releases/0.4.0/x86_64-unknown-linux-musl/objects");
    let blocked = objects.join(super::super::archive::hex(&sha));
    let replacement = Arc::new(std::sync::Mutex::new(None));
    let recorded = replacement.clone();
    *cache.hook.borrow_mut() = Some(Box::new(move |phase| {
        if let Phase::BeforeGenerationRename(name) = phase {
            std::fs::write(&blocked, b"blocked generation").unwrap();
            let path = objects.join(name);
            std::fs::rename(&path, objects.join("retained-stage")).unwrap();
            std::fs::create_dir(&path).unwrap();
            std::fs::write(path.join("sentinel"), b"unrelated replacement").unwrap();
            *recorded.lock().unwrap() = Some(path);
        }
    }));
    assert!(cache
        .publish(&request(), &bytes, &sha, &image, &budget)
        .is_err());
    let replacement = replacement
        .lock()
        .unwrap()
        .clone()
        .expect("stage replacement phase executed");
    assert_eq!(
        std::fs::read(replacement.join("sentinel")).unwrap(),
        b"unrelated replacement"
    );
}

#[test]
fn cache_group_write_and_sticky_boundaries_preserve_authority() {
    for (ancestor_mode, root_mode, allowed) in [
        (0o775, 0o700, false),
        (0o777, 0o700, false),
        (0o1777, 0o700, true),
        (0o700, 0o1777, false),
        (0o700, 0o775, false),
    ] {
        let root = private_root();
        let ancestor = root.path().join("ancestor");
        let cache = ancestor.join("cache");
        std::fs::create_dir(&ancestor).unwrap();
        std::fs::create_dir(&cache).unwrap();
        std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(ancestor_mode))
            .unwrap();
        std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(root_mode)).unwrap();
        let cancel = knock::Cancel::new();
        let budget = Budget::new(Duration::from_secs(5), &cancel);
        let authority = Authority::open(&cache, &request(), &budget);
        assert_eq!(
            authority.is_ok(),
            allowed,
            "ancestor={ancestor_mode:o}, root={root_mode:o}"
        );
        assert_eq!(
            std::fs::metadata(&ancestor).unwrap().mode() & 0o7777,
            ancestor_mode
        );
        assert_eq!(
            std::fs::metadata(&cache).unwrap().mode() & 0o7777,
            root_mode
        );
        if !allowed {
            assert_eq!(std::fs::read_dir(&cache).unwrap().count(), 0);
        }
    }
}
