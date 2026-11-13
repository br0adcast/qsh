use super::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
fn good_claims() -> sigstore_crypto::FulcioCiClaims {
    let mut c = sigstore_crypto::FulcioCiClaims::default();
    c.source_repository_uri = Some("https://github.com/br0adcast/qsh".into());
    c.source_repository_identifier = Some("1423663657".into());
    c.source_repository_ref = Some("refs/tags/v0.6.0".into());
    c.source_repository_digest = Some(COMMIT.into());
    c.source_repository_visibility_at_signing = Some("public".into());
    c
}
fn names(version: &str) -> Vec<String> {
    let mut n = Vec::new();
    for target in [
        "x86_64-unknown-linux-musl",
        "aarch64-unknown-linux-musl",
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
    ] {
        n.push(format!("qsh-{version}-{target}.tar.gz"));
    }
    for tool in ["qsh", "qshd"] {
        for arch in ["amd64", "arm64"] {
            n.push(format!("{tool}_{version}-1_{arch}.deb"));
        }
        for arch in ["x86_64", "aarch64"] {
            n.push(format!("{tool}-{version}-1.{arch}.rpm"));
        }
    }
    n.sort();
    n
}
fn sums(version: &str) -> Vec<u8> {
    names(version)
        .iter()
        .map(|n| format!("{}  {n}\n", "a".repeat(64)))
        .collect::<String>()
        .into_bytes()
}
fn stmt() -> Value {
    json!({"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"SHA256SUMS","digest":{"sha256":format!("{:x}",Sha256::digest(sums("0.6.0")))}}],"predicateType":"https://github.com/br0adcast/qsh/release-manifest/v1","predicate":{"manifest_format":"qsh-sha256sums-v1","version":"0.6.0","tag":"v0.6.0","source_commit":COMMIT}})
}
#[test]
fn required_production_claims_accept_exact_repository() {
    assert_eq!(contracts::claims("0.6.0", &good_claims()).unwrap(), COMMIT);
}
#[test]
fn canonical_twelve_product_manifest_accepts_release_and_prerelease() {
    for v in [
        "0.6.0",
        "0.6.0-rc.1",
        "0.6.0-rc1",
        "0.6.0-123",
        "0.6.0-alpha",
    ] {
        assert_eq!(contracts::manifest(v, &sums(v)).unwrap().len(), 12);
    }
}
// Assembly refuses names GitHub would rewrite, so no release with build
// metadata can be signed and its manifest has no canonical form.
#[test]
fn versions_with_unpublishable_names_have_no_manifest() {
    for v in ["0.6.0+build.7", "0.6.0-rc.1+b"] {
        assert_eq!(
            contracts::manifest(v, &sums(v)).unwrap_err(),
            "release version has no publishable product names"
        );
    }
}
// Compatibility: the `~` package spelling that v0.6.0-rc1 signed is refused,
// for the package format alone or both, so one version has one manifest.
#[test]
fn prerelease_manifest_rejects_earlier_tilde_package_spelling() {
    for (version, tilde) in [("0.6.0-rc1", "0.6.0~rc1"), ("0.6.0-rc.2", "0.6.0~rc.2")] {
        for suffix in [&[".deb"][..], &[".rpm"], &[".deb", ".rpm"]] {
            let old = names(version)
                .into_iter()
                .map(|name| {
                    if suffix.iter().any(|s| name.ends_with(s)) {
                        name.replace(version, tilde)
                    } else {
                        name
                    }
                })
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .map(|name| format!("{}  {name}\n", "a".repeat(64)))
                .collect::<String>();
            assert_eq!(
                contracts::manifest(version, old.as_bytes()).unwrap_err(),
                "noncanonical release manifest",
                "{version} {suffix:?}"
            );
        }
    }
}
#[test]
fn exact_qsh_statement_binds_original_manifest_and_commit() {
    contracts::statement(
        "0.6.0",
        &sums("0.6.0"),
        &serde_json::to_vec(&stmt()).unwrap(),
        COMMIT,
    )
    .unwrap();
}
#[test]
fn json_admits_depth_32_and_rejects_duplicate_decoded_names() {
    let s = format!("{}0{}", "[".repeat(32), "]".repeat(32));
    assert!(json::parse(s.as_bytes()).is_ok());
    assert!(json::parse(br#"{"a":1,"\u0061":2}"#).is_err());
}
#[test]
fn bounded_bundle_accepts_upstream_production_dsse() {
    super::bounded_bundle(include_bytes!(
        "../tests/data/conda-attestation.sigstore.json"
    ))
    .unwrap();
}
#[test]
fn every_required_claim_rejects_missing_wrong_and_conflicting_values() {
    let fields: [fn(&mut sigstore_crypto::FulcioCiClaims) -> &mut Option<String>; 5] = [
        |c| &mut c.source_repository_uri,
        |c| &mut c.source_repository_identifier,
        |c| &mut c.source_repository_ref,
        |c| &mut c.source_repository_digest,
        |c| &mut c.source_repository_visibility_at_signing,
    ];
    for field in fields {
        for value in [None, Some("wrong".into())] {
            let mut c = good_claims();
            *field(&mut c) = value;
            assert!(contracts::claims("0.6.0", &c).is_err());
        }
    }
    for id in [
        "01423663657",
        "1423663658",
        "1.423663657e9",
        "",
        "1423663657 ",
    ] {
        let mut c = good_claims();
        c.source_repository_identifier = Some(id.into());
        assert!(contracts::claims("0.6.0", &c).is_err());
    }
    let conflicting: [fn(&mut sigstore_crypto::FulcioCiClaims) -> &mut Option<String>; 4] = [
        |c| &mut c.build_signer_uri,
        |c| &mut c.deprecated_github.workflow_repository,
        |c| &mut c.deprecated_github.workflow_sha,
        |c| &mut c.deprecated_github.workflow_ref,
    ];
    for field in conflicting {
        let mut c = good_claims();
        *field(&mut c) = Some("conflicting".into());
        assert!(contracts::claims("0.6.0", &c).is_err());
    }
}
#[test]
fn statement_refuses_additional_missing_mismatched_and_ambiguous_authority() {
    let mutations: [fn(&mut Value); 15] = [
        |s| s["_type"] = json!("https://in-toto.io/Statement/v0.1"),
        |s| s["subject"] = json!([]),
        |s| {
            let a = s["subject"][0].clone();
            s["subject"] = json!([a.clone(), a]);
        },
        |s| s["subject"][0]["name"] = json!("other"),
        |s| s["subject"][0]["digest"]["sha256"] = json!("0".repeat(64)),
        |s| s["subject"][0]["digest"]["sha512"] = json!("0".repeat(128)),
        |s| s["predicateType"] = json!("https://example.invalid"),
        |s| s["predicate"]["manifest_format"] = json!("other"),
        |s| s["predicate"]["version"] = json!("0.6.1"),
        |s| s["predicate"]["tag"] = json!("v0.6.1"),
        |s| s["predicate"]["source_commit"] = json!("f".repeat(40)),
        |s| s["predicate"]["source_commit"] = json!(COMMIT.to_uppercase()),
        |s| s["predicate"]["extra"] = json!(true),
        |s| s["extra"] = json!(true),
        |s| {
            s["predicate"].as_object_mut().unwrap().remove("version");
        },
    ];
    for (i, m) in mutations.into_iter().enumerate() {
        let mut s = stmt();
        m(&mut s);
        assert!(
            contracts::statement(
                "0.6.0",
                &sums("0.6.0"),
                &serde_json::to_vec(&s).unwrap(),
                COMMIT
            )
            .is_err(),
            "schema {i}"
        );
    }
    let payload = serde_json::to_vec(&stmt()).unwrap();
    let mut changed = sums("0.6.0");
    changed.push(b'\n');
    assert!(contracts::statement("0.6.0", &changed, &payload, COMMIT).is_err());
    assert!(contracts::statement(
        "0.6.0",
        &sums("0.6.0"),
        &vec![b' '; STATEMENT_LIMIT + 1],
        COMMIT
    )
    .is_err());
}
#[test]
fn manifest_refuses_alternate_text_names_order_counts_hashes_and_versions() {
    let good = String::from_utf8(sums("0.6.0")).unwrap();
    for bad in [
        good.replacen("  ", " ", 1),
        good.replace('\n', "\r\n"),
        good.trim_end().to_owned(),
        good.replacen('a', "A", 1),
        good.replacen("qsh-", "../qsh-", 1),
        good.replacen("qsh-", "unknown-", 1),
        good.lines().skip(1).collect::<Vec<_>>().join("\n"),
        format!("{good}{}\n", good.lines().next().unwrap()),
        format!("{}\n", good.lines().rev().collect::<Vec<_>>().join("\n")),
    ] {
        assert!(contracts::manifest("0.6.0", bad.as_bytes()).is_err());
    }
    assert!(contracts::manifest("0.6.0", &vec![b' '; SUMS_LIMIT + 1]).is_err());
    for v in ["v0.6.0", "01.6.0", "0.6.0-01", "0.6", "0.6.0/path", ""] {
        assert!(contracts::manifest(v, &sums("0.6.0")).is_err());
    }
    let prerelease = String::from_utf8(sums("0.6.0-rc.1")).unwrap();
    assert!(contracts::manifest(
        "0.6.0-rc.1",
        prerelease
            .replace("0.6.0-rc.1-1", "0.6.0.rc.1-1")
            .as_bytes()
    )
    .is_err());
}
#[test]
fn json_depth_trailing_and_nested_duplicate_controls() {
    let too_deep = format!("{}0{}", "[".repeat(33), "]".repeat(33));
    assert!(json::parse(too_deep.as_bytes()).is_err());
    for s in [
        br#"{"x":{"a":1,"a":2}}"#.as_slice(),
        b"{} {}",
        b"[] trailing",
    ] {
        assert!(json::parse(s).is_err());
    }
}
// Cross-component: the real release assembly receives producer outputs named
// by this contract, and the SHA256SUMS it writes must be the canonical
// manifest. Assembly refuses inputs it does not expect, so drift in either
// direction fails here. Python 3 is required wherever this test runs.
fn assemble(
    version: &str,
    artifacts: &std::path::Path,
    output: &std::path::Path,
) -> std::process::Output {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/assemble-release-assets.py");
    std::process::Command::new("python3")
        .args(["-I", "-B"])
        .arg(script)
        .arg("--artifacts")
        .arg(artifacts)
        .arg("--version")
        .arg(version)
        .arg("--output")
        .arg(output)
        .output()
        .expect("python3 must be available to run release assembly")
}
#[test]
fn release_assembly_writes_the_manifest_this_contract_accepts() {
    for version in ["0.6.0", "1.2.3", "0.6.0-rc.2", "0.7.0-alpha.1", "0.6.0-rc1"] {
        let work = tempfile::tempdir().unwrap();
        let artifacts = work.path().join("artifacts");
        let products = contracts::products(version).unwrap();
        for name in &products {
            let producer = if name.contains("-apple-darwin") {
                "macos"
            } else if name.starts_with("qshd") {
                "server-packages"
            } else if ["x86_64", "amd64"].iter().any(|arch| name.contains(arch)) {
                "linux-x86_64-unknown-linux-musl"
            } else {
                "linux-aarch64-unknown-linux-musl"
            };
            let directory = artifacts.join(producer);
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(directory.join(name), name).unwrap();
        }
        let output = work.path().join("release");
        let run = assemble(version, &artifacts, &output);
        assert!(
            run.status.success() && run.stdout.is_empty() && run.stderr.is_empty(),
            "{version}: {run:?}"
        );
        let mut published: Vec<_> = std::fs::read_dir(&output)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        published.sort();
        let mut expected = products.clone();
        expected.push("SHA256SUMS".into());
        expected.sort();
        assert_eq!(published, expected, "{version}");
        let manifest = std::fs::read(output.join("SHA256SUMS")).unwrap();
        let assets = contracts::manifest(version, &manifest).unwrap();
        for name in &products {
            assert_eq!(
                assets.get(name).unwrap(),
                &<[u8; 32]>::from(Sha256::digest(name.as_bytes())),
                "{version} {name}"
            );
        }
        // Client and daemon image selection look up only these archive names.
        for target in [
            "x86_64-unknown-linux-musl",
            "aarch64-unknown-linux-musl",
            "x86_64-apple-darwin",
            "aarch64-apple-darwin",
        ] {
            assert!(assets.contains_key(&format!("qsh-{version}-{target}.tar.gz")));
        }
    }
}
#[test]
fn release_assembly_and_this_contract_both_refuse_build_metadata() {
    let work = tempfile::tempdir().unwrap();
    let version = "0.6.0+build.7";
    let run = assemble(
        version,
        &work.path().join("artifacts"),
        &work.path().join("release"),
    );
    assert_eq!(run.status.code(), Some(1), "{run:?}");
    assert_eq!(
        run.stderr,
        b"release assembly: product name would be renamed on upload\n"
    );
    assert!(contracts::products(version).is_none());
}
