//! Exercise the production build guard without changing the qualified prefix.
#[path = "../build.rs"]
mod prerequisite;

use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, ffi::OsString};

const TARGET: &str = "x86_64-unknown-linux-gnu";

struct Fixture {
    dir: tempfile::TempDir,
    manifest: serde_json::Value,
    env: BTreeMap<String, OsString>,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut artifacts = serde_json::Map::new();
        // Synthetic contents test guard decisions, not native qualification.
        for path in ["lib/libcrypto.a", "include/openssl/opensslv.h"] {
            let full = dir.path().join(path);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, b"generated guard fixture").unwrap();
            artifacts.insert(
                path.into(),
                format!("{:x}", Sha256::digest(b"generated guard fixture")).into(),
            );
        }
        Self {
            env: BTreeMap::from([
                ("OPENSSL_DIR".into(), dir.path().as_os_str().to_owned()),
                ("OPENSSL_STATIC".into(), "1".into()),
                ("DEP_OPENSSL_VERSION_NUMBER".into(), "30500090".into()),
            ]),
            dir,
            manifest: serde_json::json!({
                "identity": {
                    "target": TARGET,
                    "source": serde_json::from_str::<serde_json::Value>(
                        include_str!("../../../scripts/openssl/source.json")
                    ).unwrap()
                },
                "artifacts": artifacts
            }),
        }
    }

    fn accepted(&self) -> bool {
        std::fs::write(
            self.dir.path().join("manifest.json"),
            serde_json::to_vec(&self.manifest).unwrap(),
        )
        .unwrap();
        std::panic::catch_unwind(|| {
            prerequisite::validate(TARGET, |key| self.env.get(key).cloned())
        })
        .is_ok()
    }
}

#[test]
fn native_prerequisite_rejects_changed_provenance_target_and_artifacts() {
    let valid = Fixture::new();
    assert!(valid.accepted());
    for field in ["source", "target"] {
        let mut changed = Fixture::new();
        changed.manifest["identity"][field] = "unqualified".into();
        assert!(!changed.accepted(), "accepted changed {field}");
    }
    let changed = Fixture::new();
    std::fs::write(changed.dir.path().join("lib/libcrypto.a"), b"changed").unwrap();
    assert!(!changed.accepted());
    let mut missing = Fixture::new();
    missing.manifest["artifacts"]
        .as_object_mut()
        .unwrap()
        .remove("lib/libcrypto.a");
    assert!(!missing.accepted());
    let mut traversal = Fixture::new();
    traversal.manifest["artifacts"]["../foreign"] = "digest".into();
    assert!(!traversal.accepted());
}

#[test]
fn native_prerequisite_rejects_unqualified_selection_and_native_version() {
    for (name, value) in [
        ("OPENSSL_STATIC", "0"),
        ("OPENSSL_DIR", "relative"),
        ("OPENSSL_LIB_DIR", "/generated/override"),
        ("OPENSSL_INCLUDE_DIR", "/generated/override"),
        ("OPENSSL_LIBS", "crypto"),
        (
            "X86_64_UNKNOWN_LINUX_GNU_OPENSSL_LIB_DIR",
            "/generated/override",
        ),
        ("DEP_OPENSSL_VENDORED", "1"),
        ("DEP_OPENSSL_LIBRESSL_VERSION_NUMBER", "4000000"),
        ("DEP_OPENSSL_VERSION_NUMBER", "30500080"),
    ] {
        let mut fixture = Fixture::new();
        fixture.env.insert(name.into(), value.into());
        assert!(!fixture.accepted(), "accepted {name}");
    }
    let mut absent = Fixture::new();
    absent.env.remove("OPENSSL_DIR");
    assert!(!absent.accepted());
    let mut scoped = Fixture::new();
    scoped
        .env
        .insert("OPENSSL_DIR".into(), "invalid global".into());
    scoped.env.insert(
        "X86_64_UNKNOWN_LINUX_GNU_OPENSSL_DIR".into(),
        scoped.dir.path().as_os_str().to_owned(),
    );
    assert!(scoped.accepted());
}
