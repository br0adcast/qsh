//! Readonly integrity checks for the personal daemon's public authorization list.
//!
//! Root/current-eUID filesystem edits are trusted. Descriptors pin object identity,
//! not contents; a trusted owner may still edit an already opened file in place.
use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use rustix::fs::{self, AtFlags, FileType, Mode, OFlags};

const MAX_BYTES: usize = 1024 * 1024;
const MAX_ALIASES: usize = 40;
const MAX_ALIAS_BYTES: usize = 4096;
#[cfg(any(target_os = "linux", target_os = "android"))]
const DIRECTORY_ACCESS: OFlags = OFlags::PATH;
#[cfg(target_vendor = "apple")]
// rustix omits Apple's search-only flag; preserve libc's actual flag bits.
const DIRECTORY_ACCESS: OFlags = OFlags::from_bits_retain(libc::O_SEARCH as _);
#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
const DIRECTORY_ACCESS: OFlags = OFlags::RDONLY;
const DIRECTORY_FLAGS: OFlags = DIRECTORY_ACCESS
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const LEAF_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::NONBLOCK)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NOCTTY)
    .union(OFlags::CLOEXEC);

fn refused(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
fn trusted_owner(owner: u32, euid: u32) -> bool {
    owner == 0 || owner == euid
}
fn directory(file: File, euid: u32) -> io::Result<File> {
    let m = file.metadata()?;
    if !m.is_dir() {
        return Err(refused("authorization ancestor is not a directory"));
    }
    if !trusted_owner(m.uid(), euid) {
        return Err(refused("authorization ancestor has an untrusted owner"));
    }
    if m.mode() & 0o022 != 0 && m.mode() & 0o1000 == 0 {
        return Err(refused(
            "authorization ancestor is writable by group or others",
        ));
    }
    Ok(file)
}
fn alias_length(length: usize) -> io::Result<()> {
    if length > MAX_ALIAS_BYTES {
        return Err(refused("authorization alias target is too long"));
    }
    Ok(())
}

// Path::components normalizes away final slash/dot syntax. Keep Unix bytes and
// an explicit final dot so `regular-file/` and `regular-file/.` remain ENOTDIR.
fn parts(bytes: &[u8]) -> VecDeque<OsString> {
    let mut parts: VecDeque<_> = bytes
        .split(|b| *b == b'/')
        .filter(|p| !p.is_empty())
        .map(|p| OsString::from_vec(p.to_vec()))
        .collect();
    if bytes.ends_with(b"/") {
        parts.push_back(OsString::from("."));
    }
    parts
}
fn open_file(path: &Path, euid: u32) -> io::Result<File> {
    if path.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "empty authorization path",
        ));
    }
    // Capture cwd once per lookup, before beginning the descriptor walk. This
    // does not change the verifier's existing per-attempt relative-path meaning.
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let root = directory(
        File::from(fs::open("/", DIRECTORY_FLAGS, Mode::empty())?),
        euid,
    )?;
    let mut stack = vec![root];
    let mut pending = parts(absolute.as_os_str().as_bytes());
    let mut aliases = 0;
    while let Some(name) = pending.pop_front() {
        if name == "." || name == ".." {
            if name == ".." && stack.len() > 1 {
                stack.pop();
            }
            if pending.is_empty() {
                return Err(refused("authorization path names a directory"));
            }
            continue;
        }
        let current = stack.last().expect("root stays pinned");
        let stat = fs::statat(current, &name, AtFlags::SYMLINK_NOFOLLOW)?;
        if FileType::from_raw_mode(stat.st_mode) == FileType::Symlink {
            if !trusted_owner(stat.st_uid, euid) {
                return Err(refused("authorization alias has an untrusted owner"));
            }
            aliases += 1;
            if aliases > MAX_ALIASES {
                return Err(refused("authorization alias limit exceeded"));
            }
            let mut buffer = [0u8; MAX_ALIAS_BYTES + 1];
            let count = fs::readlinkat_raw(current, &name, &mut buffer[..])?;
            alias_length(count)?;
            let target = &buffer[..count];
            if target.starts_with(b"/") {
                stack.truncate(1);
            }
            let mut target = parts(target);
            target.append(&mut pending);
            pending = target;
            continue;
        }
        if pending.is_empty() {
            let file = File::from(fs::openat(current, &name, LEAF_FLAGS, Mode::empty())?);
            let m = file.metadata()?;
            if !m.is_file() {
                return Err(refused("authorization source is not a regular file"));
            }
            if !trusted_owner(m.uid(), euid) {
                return Err(refused("authorization source has an untrusted owner"));
            }
            if m.mode() & 0o022 != 0 {
                return Err(refused(
                    "authorization source is writable by group or others",
                ));
            }
            return Ok(file);
        }
        stack.push(directory(
            File::from(fs::openat(current, &name, DIRECTORY_FLAGS, Mode::empty())?),
            euid,
        )?);
    }
    Err(refused("authorization path names a directory"))
}
fn read_opened(file: File) -> io::Result<String> {
    let mut bytes = Vec::new();
    file.take((MAX_BYTES + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "authorization source is larger than 1MiB",
        ));
    }
    String::from_utf8(bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "authorization source is invalid UTF-8",
        )
    })
}
pub(crate) fn read(path: &Path) -> io::Result<String> {
    read_opened(open_file(path, rustix::process::geteuid().as_raw())?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn fixture() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }
    fn mode(path: &Path, bits: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits)).unwrap();
    }
    fn file(path: &Path) {
        std::fs::write(path, "public keys\n").unwrap();
        mode(path, 0o644);
    }
    fn uid() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    #[test]
    fn trusted_alias_bounds_are_finite() {
        let d = fixture();
        let p = d.path().join("keys");
        file(&p);
        for i in 0..41 {
            symlink(
                if i == 0 {
                    "keys".into()
                } else {
                    format!("alias{}", i - 1)
                },
                d.path().join(format!("alias{i}")),
            )
            .unwrap();
        }
        // Isolate the controlled 40/41 aliases from platform temp ancestors
        // such as Darwin /var. Other lookups below retain the original route.
        let physical = std::fs::canonicalize(d.path()).unwrap();
        assert_eq!(read(&physical.join("alias39")).unwrap(), "public keys\n");
        assert!(read(&physical.join("alias40")).is_err());
        symlink("loop", d.path().join("loop")).unwrap();
        assert!(read(&d.path().join("loop")).is_err());
        for suffix in ["keys/", "keys/.", "keys/.."] {
            assert!(read(&d.path().join(suffix)).is_err(), "{suffix}");
        }
        symlink("keys/", d.path().join("slash")).unwrap();
        assert!(read(&d.path().join("slash")).is_err());
        symlink("keys/.", d.path().join("dot")).unwrap();
        assert!(read(&d.path().join("dot")).is_err());
        let sub = d.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        mode(&sub, 0o700);
        symlink("sub/../alias0", d.path().join("parented")).unwrap();
        assert!(read(&d.path().join("parented")).is_ok());
        symlink(d.path(), d.path().join("parent")).unwrap();
        assert!(read(&d.path().join("parent/keys")).is_ok());
        assert!(alias_length(4096).is_ok());
        assert!(alias_length(4097).is_err());
        assert!(trusted_owner(0, 123));
        assert!(trusted_owner(123, 123));
        assert!(!trusted_owner(124, 123));
    }
    #[test]
    fn descriptor_replacement_keeps_opened_object() {
        let d = fixture();
        let parent = d.path().join("parent");
        std::fs::create_dir(&parent).unwrap();
        mode(&parent, 0o700);
        let p = parent.join("keys");
        file(&p);
        let opened = open_file(&p, uid()).unwrap();
        std::fs::rename(&parent, d.path().join("old")).unwrap();
        std::fs::create_dir(&parent).unwrap();
        mode(&parent, 0o700);
        file(&p);
        mode(&p, 0o666);
        assert_eq!(read_opened(opened).unwrap(), "public keys\n");
        assert!(read(&p).is_err());
        let p = d.path().join("leaf");
        file(&p);
        let opened = open_file(&p, uid()).unwrap();
        std::fs::rename(&p, d.path().join("old-leaf")).unwrap();
        symlink(parent.join("keys"), &p).unwrap();
        assert_eq!(read_opened(opened).unwrap(), "public keys\n");
        assert!(read(&p).is_err());
    }
    #[test]
    fn growth_after_open_is_bounded() {
        let d = fixture();
        let p = d.path().join("keys");
        file(&p);
        let opened = open_file(&p, uid()).unwrap();
        let mut writer = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        writer.write_all(&vec![b'x'; MAX_BYTES]).unwrap();
        assert!(read_opened(opened).is_err());
        std::fs::write(&p, vec![b'x'; MAX_BYTES]).unwrap();
        assert_eq!(read(&p).unwrap().len(), MAX_BYTES);
        writer.write_all(b"x").unwrap();
        assert!(read(&p).is_err());
    }
    #[test]
    fn nonregular_and_writable_objects_are_refused() {
        let d = fixture();
        let p = d.path().join("keys");
        file(&p);
        for bits in [0o664, 0o646] {
            mode(&p, bits);
            assert!(read(&p).is_err());
        }
        mode(&p, 0o644);
        for bits in [0o775, 0o707] {
            mode(d.path(), bits);
            assert!(read(&p).is_err());
        }
        mode(d.path(), 0o700);
        assert!(read(d.path()).is_err());
        assert!(read(Path::new("/dev/zero")).is_err());
        let fifo = d.path().join("fifo");
        nix::unistd::mkfifo(
            &fifo,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        assert!(read(&fifo).is_err());
    }
    #[test]
    fn search_only_and_sticky_ancestors_are_supported() {
        let d = fixture();
        let sub = d.path().join("search");
        std::fs::create_dir(&sub).unwrap();
        let p = sub.join("keys");
        file(&p);
        mode(&sub, 0o111);
        assert_eq!(
            std::fs::metadata(&sub).unwrap().permissions().mode() & 0o7777,
            0o111
        );
        let result = read(&p);
        mode(&sub, 0o700);
        assert_eq!(result.unwrap(), "public keys\n");
        mode(&sub, 0o1777);
        assert_eq!(read(&p).unwrap(), "public keys\n");
        mode(&sub, 0o700);
    }
    #[test]
    fn public_hardlinks_and_invalid_utf8_have_explicit_results() {
        let d = fixture();
        let p = d.path().join("keys");
        file(&p);
        let link = d.path().join("hard");
        std::fs::hard_link(&p, &link).unwrap();
        assert!(read(&link).is_ok());
        mode(&p, 0o600);
        assert!(read(&link).is_ok());
        let bytes = d
            .path()
            .join(std::ffi::OsString::from_vec(b"keys-\xff".to_vec()));
        file(&bytes);
        assert!(read(&bytes).is_ok());
        std::fs::write(&p, [0xff]).unwrap();
        assert_eq!(read(&p).unwrap_err().kind(), io::ErrorKind::InvalidData);
    }
}
