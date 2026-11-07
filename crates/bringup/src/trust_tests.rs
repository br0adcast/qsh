use super::*;
use std::{fs, os::unix::fs::PermissionsExt, process::Command};

fn native_os() -> ServerOs {
    if cfg!(target_os = "macos") {
        ServerOs::Darwin
    } else {
        ServerOs::Linux
    }
}

fn inspect(path: &std::path::Path, purpose: Purpose) -> Result<String, BringUpError> {
    let script = command(path.to_str().unwrap(), native_os(), purpose)?;
    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .env("HISTFILE", "/dev/null")
        .output()
        .unwrap();
    parse(
        output.status.code().unwrap_or(-1),
        std::str::from_utf8(&output.stdout).unwrap(),
    )
}
fn mode(path: &std::path::Path, value: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(value)).unwrap();
}
fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
    let root = tempfile::tempdir_in(fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
    mode(root.path(), 0o700);
    let file = root.path().join("qshd");
    fs::write(&file, b"must never execute").unwrap();
    mode(&file, 0o700);
    (root, file)
}
#[test]
fn trust_refuses_writable_leaf_even_inside_private_home() {
    let (_root, file) = fixture();
    mode(&file, 0o777);
    assert!(inspect(&file, Purpose::Execute).is_err());
}
#[test]
fn trust_private_home_allows_writable_inner_directory() {
    let (root, file) = fixture();
    let cache = root.path().join("cache");
    fs::create_dir(&cache).unwrap();
    mode(&cache, 0o770);
    let target = cache.join("qshd");
    fs::rename(file, &target).unwrap();
    assert_eq!(
        inspect(&target, Purpose::Execute).unwrap(),
        target.to_str().unwrap()
    );
}
#[test]
fn trust_rejects_reachable_writable_parent_and_unsafe_private_boundary() {
    let (root, file) = fixture();
    for permissions in [0o777, 0o760] {
        mode(root.path(), permissions);
        assert!(inspect(&file, Purpose::Execute).is_err());
    }
}
#[test]
fn trust_relative_and_directory_links_resolve_before_dotdot() {
    let (root, file) = fixture();
    let dir = root.path().join("cellar");
    fs::create_dir(&dir).unwrap();
    fs::rename(file, dir.join("qshd")).unwrap();
    std::os::unix::fs::symlink("cellar/qshd", root.path().join("brew")).unwrap();
    assert_eq!(
        inspect(&root.path().join("brew"), Purpose::Execute).unwrap(),
        dir.join("qshd").to_str().unwrap()
    );
    std::os::unix::fs::symlink("cellar", root.path().join("dirlink")).unwrap();
    assert_eq!(
        inspect(
            &root.path().join("dirlink/../cellar/qshd"),
            Purpose::Execute
        )
        .unwrap(),
        dir.join("qshd").to_str().unwrap()
    );
}
#[test]
fn trust_rejects_dangling_cyclic_and_escaped_links() {
    let (root, _) = fixture();
    std::os::unix::fs::symlink("loop", root.path().join("loop")).unwrap();
    assert!(inspect(&root.path().join("loop"), Purpose::Execute).is_err());
    std::os::unix::fs::symlink("missing", root.path().join("dangling")).unwrap();
    assert!(inspect(&root.path().join("dangling"), Purpose::Execute).is_err());
    let other = tempfile::tempdir_in(fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
    mode(other.path(), 0o700);
    let target = other.path().join("qshd");
    fs::write(&target, b"unused").unwrap();
    mode(&target, 0o700);
    std::os::unix::fs::symlink(&target, root.path().join("escape")).unwrap();
    assert_eq!(
        inspect(&root.path().join("escape"), Purpose::Execute).unwrap(),
        target.to_str().unwrap()
    );
    mode(other.path(), 0o777);
    assert!(inspect(&root.path().join("escape"), Purpose::Execute).is_err());
}
#[test]
fn trust_quotes_spaces_and_control_limits() {
    let (root, file) = fixture();
    let target = root.path().join("qshd it's safe");
    fs::rename(file, &target).unwrap();
    assert_eq!(
        inspect(&target, Purpose::Execute).unwrap(),
        target.to_str().unwrap()
    );
    assert!(command("/tmp/bad\npath", ServerOs::Linux, Purpose::Execute).is_err());
    assert!(command(
        &format!("/{}", "a".repeat(4096)),
        ServerOs::Linux,
        Purpose::Execute
    )
    .is_err());
    assert!(inspect(
        &root.path().join("a/".repeat(257)),
        Purpose::InstallDirectory
    )
    .is_err());
}
#[test]
fn trust_leaf_must_be_regular_executable_without_special_bits() {
    let (root, file) = fixture();
    assert!(inspect(root.path(), Purpose::Execute).is_err());
    mode(&file, 0o600);
    assert!(inspect(&file, Purpose::Execute).is_err());
    mode(&file, 0o4700);
    assert!(inspect(&file, Purpose::Execute).is_err());
    assert!(inspect(root.path(), Purpose::InstallDirectory).is_ok());
}
#[test]
fn trust_parser_fails_closed_on_extra_or_missing_records() {
    for (code, text) in [
        (1, "QSH-TRUST /safe\n"),
        (0, "/safe\n"),
        (0, "QSH-TRUST /safe\nextra\n"),
        (0, "QSH-TRUST /unsafe\x1b\n"),
    ] {
        assert!(parse(code, text).is_err());
    }
}
#[test]
fn trust_managed_file_refuses_final_link_but_accepts_safe_nonexecutables_and_absence() {
    let (root, file) = fixture();
    mode(&file, 0o600);
    assert!(inspect(&file, Purpose::InstallFile).is_ok());
    assert!(inspect(&root.path().join("missing"), Purpose::InstallFile).is_ok());
    std::os::unix::fs::symlink("qshd", root.path().join("alias")).unwrap();
    assert!(inspect(&root.path().join("alias"), Purpose::InstallFile).is_err());
}
#[test]
fn trust_does_not_inherit_privacy_across_dotdot() {
    let (root, _) = fixture();
    let private = root.path().join("private");
    fs::create_dir(&private).unwrap();
    mode(&private, 0o700);
    let public = root.path().join("public");
    fs::create_dir(&public).unwrap();
    mode(&public, 0o777);
    mode(root.path(), 0o755);
    let file = public.join("qshd");
    fs::write(&file, b"unused").unwrap();
    mode(&file, 0o700);
    assert!(inspect(&private.join("../public/qshd"), Purpose::Execute).is_err());
}
#[test]
fn trust_sticky_directory_is_traversable_but_not_a_destination() {
    let (root, file) = fixture();
    mode(root.path(), 0o1777);
    assert!(inspect(&file, Purpose::Execute).is_ok());
    assert!(inspect(root.path(), Purpose::InstallDirectory).is_err());
    assert!(inspect(&root.path().join("missing"), Purpose::InstallFile).is_err());
}
#[test]
fn trust_rejects_foreign_ownership_including_links() {
    let (root, file) = fixture();
    std::os::unix::fs::symlink("qshd", root.path().join("link")).unwrap();
    let link = root.path().join("link");
    for boundary in [file.as_path(), link.as_path(), root.path()] {
        let injection = format!(
            "if [ \"$boundary\" = {} ]; then owner=123456789; fi\n    [ \"$owner\" = 0 ] ||",
            crate::shell::quote(boundary.to_str().unwrap())
        );
        let candidate = if boundary == root.path() {
            file.as_path()
        } else {
            boundary
        };
        let script = command(candidate.to_str().unwrap(), native_os(), Purpose::Execute)
            .unwrap()
            .replace("[ \"$owner\" = 0 ] ||", &injection);
        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .output()
            .unwrap();
        assert!(parse(
            output.status.code().unwrap(),
            std::str::from_utf8(&output.stdout).unwrap()
        )
        .is_err());
    }
}
#[test]
fn trust_missing_tools_and_malformed_metadata_fail_closed() {
    let (_root, file) = fixture();
    let script = command(file.to_str().unwrap(), native_os(), Purpose::Execute).unwrap();
    for bad in [
        script
            .replace("id=/usr/bin/id", "id=/nonexistent/id")
            .replace("id=/bin/id", "id=/nonexistent/id"),
        script.replace(
            "bits=${record%%:*}",
            "record=not-metadata; bits=${record%%:*}",
        ),
    ] {
        let output = Command::new("/bin/sh").arg("-c").arg(bad).output().unwrap();
        assert!(parse(
            output.status.code().unwrap(),
            std::str::from_utf8(&output.stdout).unwrap()
        )
        .is_err());
    }
}
#[test]
fn trust_link_and_component_limits_are_enforced_on_existing_paths() {
    let (root, file) = fixture();
    for n in 0..41 {
        std::os::unix::fs::symlink(
            if n == 0 {
                "qshd".into()
            } else {
                format!("link{}", n - 1)
            },
            root.path().join(format!("link{n}")),
        )
        .unwrap();
    }
    let accepted_links = 40.min(200 / root.path().components().count());
    assert!(inspect(
        &root.path().join(format!("link{}", accepted_links - 1)),
        Purpose::Execute
    )
    .is_ok());
    assert!(inspect(&root.path().join("link40"), Purpose::Execute).is_err());
    let repeated = format!("{}/{}qshd", root.path().display(), "./".repeat(257));
    assert!(inspect(std::path::Path::new(&repeated), Purpose::Execute).is_err());
    let unicode = root.path().join("qshd-λ");
    fs::rename(file, &unicode).unwrap();
    assert_eq!(
        inspect(&unicode, Purpose::Execute).unwrap(),
        unicode.to_str().unwrap()
    );
}
#[cfg(target_os = "linux")]
#[test]
fn trust_darwin_metadata_format_fixture() {
    let (root, file) = fixture();
    let utility = root.path().join("stat-fixture");
    fs::write(&utility,b"#!/bin/sh\n[ \"$1\" = -f ] && [ \"$2\" = '%Lp:%u' ] && [ \"$#\" = 3 ] || exit 2\nexec /usr/bin/stat -c '%a:%u' -- \"$3\"\n").unwrap();
    mode(&utility, 0o700);
    let script = command(file.to_str().unwrap(), ServerOs::Darwin, Purpose::Execute)
        .unwrap()
        .replace(
            "stat=/usr/bin/stat",
            &format!("stat={}", shell::quote(utility.to_str().unwrap())),
        );
    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .output()
        .unwrap();
    assert_eq!(
        parse(
            output.status.code().unwrap(),
            std::str::from_utf8(&output.stdout).unwrap()
        )
        .unwrap(),
        file.to_str().unwrap()
    );
}
