use super::*;
use std::os::unix::fs::{symlink, DirBuilderExt};

// Deliberate noncredential bytes for filesystem phases, never a real keypair.
const BYTES: [u8; 64] = [17; 64];
fn private_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}
fn make_dir(path: &Path) {
    std::fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}

#[derive(Default)]
struct Observe {
    reads: usize,
    repairs: usize,
    fail_repair: bool,
    skip_repair: bool,
}
impl ReadIo for Observe {
    fn repair(&mut self, file: &File) -> io::Result<()> {
        self.repairs += 1;
        if self.fail_repair {
            return Err(io::Error::from_raw_os_error(nix::libc::EPERM));
        }
        if !self.skip_repair {
            FileIo.repair(file)?;
        }
        Ok(())
    }
    fn read(&mut self, file: &mut File, bytes: &mut [u8]) -> io::Result<usize> {
        self.reads += 1;
        file.read(bytes)
    }
}

fn key(path: &Path, mode: u32) {
    std::fs::write(path, BYTES).unwrap();
    std::fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
}
fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().mode() & 0o777
}

#[test]
fn owner_only_readable_identity_is_not_changed() {
    let dir = private_dir();
    let path = dir.path().join("key");
    key(&path, 0o400);
    let mut io = Observe::default();
    let loaded = read(&path, Uid::effective(), &mut io).unwrap();
    assert_eq!(loaded.bytes, BYTES);
    assert_eq!(loaded.repaired_mode, None);
    assert!(io.reads > 0);
    assert_eq!(io.repairs, 0);
    assert_eq!(mode(&path), 0o400);
}

#[test]
fn permissive_verified_file_is_repaired_before_its_bytes_are_read() {
    let dir = private_dir();
    let path = dir.path().join("key");
    key(&path, 0o644);
    struct Checked;
    impl ReadIo for Checked {
        fn read(&mut self, file: &mut File, bytes: &mut [u8]) -> io::Result<usize> {
            assert_eq!(file.metadata()?.mode() & 0o777, 0o600);
            file.read(bytes)
        }
    }
    let loaded = read(&path, Uid::effective(), &mut Checked).unwrap();
    assert_eq!(loaded.bytes, BYTES);
    assert_eq!(loaded.repaired_mode, Some(0o644));
    assert_eq!(mode(&path), 0o600);
}

#[test]
fn denied_or_ineffective_permission_repair_reads_zero_bytes() {
    let dir = private_dir();
    let path = dir.path().join("key");
    for fail in [true, false] {
        key(&path, 0o644);
        let mut io = Observe {
            fail_repair: fail,
            skip_repair: !fail,
            ..Observe::default()
        };
        let error = read(&path, Uid::effective(), &mut io).err().unwrap();
        assert!(error.to_string().contains("repair"));
        assert_eq!(io.repairs, 1);
        assert_eq!(io.reads, 0);
        assert_eq!(mode(&path), 0o644);
        assert_eq!(std::fs::read(&path).unwrap(), BYTES);
    }
}

#[test]
fn linked_nonregular_corrupt_and_wrong_owner_files_never_reach_the_reader() {
    let dir = private_dir();
    let path = dir.path().join("key");
    let link = dir.path().join("link");
    key(&path, 0o644);
    symlink(&path, &link).unwrap();
    let mut io = Observe::default();
    assert!(read(&link, Uid::effective(), &mut io).is_err());
    std::fs::remove_file(&link).unwrap();
    std::fs::hard_link(&path, &link).unwrap();
    assert!(read(&path, Uid::effective(), &mut io).is_err());
    std::fs::remove_file(&link).unwrap();
    assert!(read_opened(
        File::open(&path).unwrap(),
        Uid::from_raw(Uid::effective().as_raw() + 1),
        &mut io
    )
    .is_err());
    let directory = dir.path().join("directory");
    make_dir(&directory);
    assert!(read(&directory, Uid::effective(), &mut io).is_err());
    std::fs::write(&path, b"corrupt").unwrap();
    assert!(read(&path, Uid::effective(), &mut io).is_err());
    assert_eq!(io.reads, 0);
    assert_eq!(io.repairs, 0);
    assert_eq!(mode(&path), 0o644);
    assert_eq!(std::fs::read(&path).unwrap(), b"corrupt");
}

#[test]
fn writable_parent_is_refused_before_reading_or_missing_leaf() {
    let dir = private_dir();
    let unsafe_dir = dir.path().join("unsafe");
    make_dir(&unsafe_dir);
    key(&unsafe_dir.join("key"), 0o600);
    std::fs::set_permissions(&unsafe_dir, Permissions::from_mode(0o777)).unwrap();
    let mut io = Observe::default();
    for leaf in ["key", "missing"] {
        let error = read(&unsafe_dir.join(leaf), Uid::effective(), &mut io)
            .err()
            .unwrap();
        assert!(error.to_string().contains("parent is writable"));
    }
    assert_eq!(io.reads, 0);
    assert_eq!(io.repairs, 0);
}

#[test]
fn trusted_sticky_parent_and_validated_alias_targets_are_supported() {
    let dir = private_dir();
    let actual = dir.path().join("actual");
    make_dir(&actual);
    key(&actual.join("key"), 0o600);
    std::fs::set_permissions(&actual, Permissions::from_mode(0o1777)).unwrap();
    symlink("actual", dir.path().join("relative")).unwrap();
    symlink(&actual, dir.path().join("absolute")).unwrap();
    let mut io = Observe::default();
    for name in ["actual", "relative", "absolute"] {
        assert_eq!(
            read(
                &dir.path().join(name).join("key"),
                Uid::effective(),
                &mut io
            )
            .unwrap()
            .bytes,
            BYTES
        );
    }
    std::fs::set_permissions(&actual, Permissions::from_mode(0o777)).unwrap();
    let reads = io.reads;
    assert!(read(&dir.path().join("relative/key"), Uid::effective(), &mut io).is_err());
    assert_eq!(io.reads, reads, "alias must validate target parents too");
    let safe = dir.path().join("safe");
    make_dir(&safe);
    key(&safe.join("key"), 0o600);
    symlink("actual/../safe", dir.path().join("through-unsafe")).unwrap();
    assert!(read(
        &dir.path().join("through-unsafe/key"),
        Uid::effective(),
        &mut io
    )
    .is_err());
    assert_eq!(
        io.reads, reads,
        "parent components must not erase an unsafe traversal"
    );
}

#[test]
fn alias_loops_are_bounded_without_reading_a_key() {
    let dir = private_dir();
    symlink("loop", dir.path().join("loop")).unwrap();
    let mut io = Observe::default();
    let error = read(&dir.path().join("loop/key"), Uid::effective(), &mut io)
        .err()
        .unwrap();
    assert!(error.to_string().contains("alias limit"));
    assert_eq!(io.reads, 0);
}

#[test]
fn anchored_leaf_repair_and_read_do_not_follow_a_replacement_path() {
    let dir = private_dir();
    let path = dir.path().join("key");
    key(&path, 0o644);
    let (parent, leaf) = parent(&path, Uid::effective()).unwrap();
    let opened = owned(
        fcntl::openat(
            Some(parent.as_raw_fd()),
            leaf.as_os_str(),
            LEAF_FLAGS,
            Mode::empty(),
        )
        .unwrap(),
    );
    let original = dir.path().join("original");
    std::fs::rename(&path, &original).unwrap();
    std::fs::write(&path, [19; 64]).unwrap();
    std::fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        read_opened(opened, Uid::effective(), &mut FileIo)
            .unwrap()
            .bytes,
        BYTES
    );
    assert_eq!(mode(&original), 0o600);
    assert_eq!(mode(&path), 0o644);
    assert_eq!(std::fs::read(&path).unwrap(), [19; 64]);
}

#[test]
fn parent_descriptor_survives_rename_without_following_a_planted_directory() {
    let dir = private_dir();
    let path = dir.path().join("parent");
    make_dir(&path);
    key(&path.join("key"), 0o600);
    let (anchored, leaf) = parent(&path.join("key"), Uid::effective()).unwrap();
    std::fs::rename(&path, dir.path().join("original")).unwrap();
    make_dir(&path);
    std::fs::set_permissions(&path, Permissions::from_mode(0o777)).unwrap();
    let opened = owned(
        fcntl::openat(
            Some(anchored.as_raw_fd()),
            leaf.as_os_str(),
            LEAF_FLAGS,
            Mode::empty(),
        )
        .unwrap(),
    );
    assert_eq!(
        read_opened(opened, Uid::effective(), &mut FileIo)
            .unwrap()
            .bytes,
        BYTES
    );
    let mut io = Observe::default();
    assert!(read(&path.join("key"), Uid::effective(), &mut io).is_err());
    assert_eq!(io.reads, 0);
}

#[test]
fn exact_alias_limit_and_relative_parent_targets_are_validated() {
    let dir = private_dir();
    let actual = dir.path().join("actual");
    make_dir(&actual);
    key(&actual.join("key"), 0o600);
    let sub = dir.path().join("sub");
    make_dir(&sub);
    symlink("../actual", sub.join("parent-alias")).unwrap();
    assert_eq!(
        read(&sub.join("parent-alias/key"), Uid::effective(), &mut FileIo)
            .unwrap()
            .bytes,
        BYTES
    );
    for index in (0..=MAX_ALIASES).rev() {
        let target = if index == MAX_ALIASES {
            "actual".to_string()
        } else {
            format!("alias-{}", index + 1)
        };
        symlink(target, dir.path().join(format!("alias-{index}"))).unwrap();
    }
    let mut io = Observe::default();
    assert_eq!(
        read(&dir.path().join("alias-1/key"), Uid::effective(), &mut io)
            .unwrap()
            .bytes,
        BYTES
    );
    let calls = io.reads;
    assert!(
        read(&dir.path().join("alias-0/key"), Uid::effective(), &mut io)
            .err()
            .unwrap()
            .to_string()
            .contains("alias limit")
    );
    assert_eq!(io.reads, calls);
}
