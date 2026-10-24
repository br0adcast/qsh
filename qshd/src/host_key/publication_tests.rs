use super::*;

#[test]
fn staging_collision_limit_preserves_unrelated_file() {
    let dir = tempfile::tempdir().unwrap();
    let parent = File::open(dir.path()).unwrap();
    let name = CString::new(".qshd-host-key-collision").unwrap();
    std::fs::write(dir.path().join(name.to_str().unwrap()), b"foreign").unwrap();
    let mut attempts = 0;
    let error = create_with(&parent, || {
        attempts += 1;
        Ok(name.clone())
    })
    .err()
    .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(attempts, 32);
    assert_eq!(
        std::fs::read(dir.path().join(name.to_str().unwrap())).unwrap(),
        b"foreign"
    );
}
