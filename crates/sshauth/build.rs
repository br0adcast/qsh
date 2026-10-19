use sha2::{Digest, Sha256};
use std::path::{Component, PathBuf};

#[cfg_attr(test, allow(dead_code))]
fn main() {
    let target = std::env::var("TARGET").expect("Cargo target");
    validate(&target, |name| std::env::var_os(name));
}

pub fn validate(target: &str, env: impl Fn(&str) -> Option<std::ffi::OsString>) {
    println!("cargo:rustc-env=QSH_NATIVE_TARGET={target}");
    let prefix = target.to_uppercase().replace('-', "_");
    let mut native = PathBuf::new();
    for suffix in ["OPENSSL_DIR", "OPENSSL_STATIC"] {
        let scoped = format!("{prefix}_{suffix}");
        println!("cargo:rerun-if-env-changed={scoped}");
        println!("cargo:rerun-if-env-changed={suffix}");
        let value = env(&scoped)
            .or_else(|| env(suffix))
            .and_then(|v| v.into_string().ok());
        assert!(value.as_ref().is_some_and(|value| !value.is_empty()),
            "use scripts/build-openssl.sh and explicitly set {scoped} and {prefix}_OPENSSL_STATIC=1");
        if suffix == "OPENSSL_DIR" {
            native = PathBuf::from(value.as_ref().unwrap());
        }
        if suffix == "OPENSSL_STATIC" {
            assert_eq!(
                value.as_deref(),
                Some("1"),
                "native crypto must be linked statically"
            );
        }
    }
    for suffix in ["OPENSSL_LIB_DIR", "OPENSSL_INCLUDE_DIR", "OPENSSL_LIBS"] {
        for name in [suffix.to_owned(), format!("{prefix}_{suffix}")] {
            println!("cargo:rerun-if-env-changed={name}");
            assert!(
                env(&name).is_none(),
                "{name} would override the qualified native prefix"
            );
        }
    }
    assert!(
        env("DEP_OPENSSL_VENDORED").is_none(),
        "Cargo-vendored native sources are not the qualified prerequisite"
    );
    assert!(
        native.is_absolute(),
        "OPENSSL_DIR must name the absolute qualified prefix"
    );
    let manifest_path = native.join("manifest.json");
    println!("cargo:rerun-if-changed={}", manifest_path.display());
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).expect("qualified native manifest"))
            .expect("valid native manifest");
    let source: serde_json::Value =
        serde_json::from_str(include_str!("../../scripts/openssl/source.json"))
            .expect("pinned source manifest");
    assert_eq!(
        manifest["identity"]["source"], source,
        "native source provenance differs from the repository pin"
    );
    assert_eq!(
        manifest["identity"]["target"].as_str(),
        Some(target),
        "native target does not match Cargo target"
    );
    let artifacts = manifest["artifacts"]
        .as_object()
        .expect("native artifact inventory");
    for required in ["lib/libcrypto.a", "include/openssl/opensslv.h"] {
        assert!(
            artifacts.contains_key(required),
            "native inventory omits {required}"
        );
    }
    for (relative, expected) in artifacts {
        let relative = std::path::Path::new(relative);
        assert!(
            relative
                .components()
                .all(|part| matches!(part, Component::Normal(_))),
            "invalid native artifact path"
        );
        let path = native.join(relative);
        println!("cargo:rerun-if-changed={}", path.display());
        let bytes = std::fs::read(path).expect("complete native artifact");
        assert_eq!(
            format!("{:x}", Sha256::digest(bytes)),
            expected.as_str().expect("native digest"),
            "native artifact changed after qualification"
        );
    }
    assert!(
        env("DEP_OPENSSL_LIBRESSL_VERSION_NUMBER").is_none(),
        "LibreSSL is not the qualified RSA backend"
    );
    let version = env("DEP_OPENSSL_VERSION_NUMBER")
        .and_then(|v| v.into_string().ok())
        .expect("OpenSSL dependency version");
    assert_eq!(
        u64::from_str_radix(&version, 16).ok(),
        Some(0x30500090),
        "the native RSA backend requires the verified OpenSSL 3.5.9 prerequisite"
    );
}
