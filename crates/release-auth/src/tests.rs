use super::*;
const GOLDEN: &[u8] = include_bytes!("../tests/data/conda-attestation.sigstore.json");
const ARTIFACT: &[u8] = include_bytes!("../tests/data/signed-package-2.1.0-hb0f4dca_0.conda");
const IDENTITY: &str =
    "https://github.com/prefix-dev/sigstore-example/.github/workflows/action.yaml@refs/heads/main";
const ISSUER: &str = "https://token.actions.githubusercontent.com";
#[test]
fn public_production_bundle_verifies_offline_with_all_checks() {
    let (result, _) = verify_crypto(
        ARTIFACT,
        GOLDEN,
        ROOTS,
        IdentityMatcher::Uri(IDENTITY.into()),
        ISSUER,
    )
    .expect("public production golden bundle");
    assert!(result.certificate_verified());
    assert!(result.sct_verified());
    assert!(result.tlog_verified());
    assert!(result.identity_policy_checked());
    assert!(!result.verified_timestamps().is_empty());
}
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
fn changed(mutator: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut v: Value = serde_json::from_slice(GOLDEN).unwrap();
    mutator(&mut v);
    serde_json::to_vec(&v).unwrap()
}
fn flip_base64(v: &mut Value) {
    let mut b = STANDARD.decode(v.as_str().unwrap()).unwrap();
    b[0] ^= 1;
    *v = json!(STANDARD.encode(b));
}
#[test]
fn crypto_rejects_artifact_signature_checkpoint_inclusion_certificate_and_identity_changes() {
    let mut artifact = ARTIFACT.to_vec();
    artifact[0] ^= 1;
    assert!(verify_crypto(&artifact, GOLDEN, ROOTS, IDENTITY, ISSUER).is_err());
    let mutations: [fn(&mut Value); 4] = [
        |v| flip_base64(&mut v["dsseEnvelope"]["signatures"][0]["sig"]),
        |v| {
            let e = &mut v["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]
                ["checkpoint"]["envelope"];
            *e = json!(e
                .as_str()
                .unwrap()
                .replacen("rekor.sigstore.dev", "other.sigstore.dev", 1));
        },
        |v| {
            flip_base64(
                &mut v["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["hashes"][0],
            )
        },
        |v| flip_base64(&mut v["verificationMaterial"]["certificate"]["rawBytes"]),
    ];
    for mutate in mutations {
        assert!(verify_crypto(ARTIFACT, &changed(mutate), ROOTS, IDENTITY, ISSUER).is_err());
    }
    assert!(verify_crypto(ARTIFACT, GOLDEN, ROOTS, IDENTITY, "https://example.invalid").is_err());
    assert!(verify_crypto(
        ARTIFACT,
        GOLDEN,
        ROOTS,
        "https://example.invalid/workflow",
        ISSUER
    )
    .is_err());
    // A valid upstream signature is not authorized to issue qsh releases.
    assert!(verify_manifest("0.6.0", ARTIFACT, GOLDEN).is_err());
}
#[test]
fn historical_expired_leaf_and_root_rotation_use_real_crypto() {
    let (result, _) = verify_crypto(ARTIFACT, GOLDEN, ROOTS, IDENTITY, ISSUER).unwrap();
    let cert = result.certificate().unwrap();
    assert!(cert.not_after.to_string().as_str() < "2026-11-04T00:00:00Z");
    assert!(result
        .verified_timestamps()
        .iter()
        .all(|t| *t >= cert.not_before && *t <= cert.not_after));
    let mut old: Value = serde_json::from_str(ROOTS).unwrap();
    old["tlogs"].as_array_mut().unwrap().truncate(1);
    // The reviewed production snapshot adds the next Rekor key and retains the
    // historical anchor. Both sets must still verify the historical signature.
    verify_crypto(ARTIFACT, GOLDEN, &old.to_string(), IDENTITY, ISSUER).unwrap();
    verify_crypto(ARTIFACT, GOLDEN, ROOTS, IDENTITY, ISSUER).unwrap();
    old["tlogs"] = json!([]);
    assert!(verify_crypto(ARTIFACT, GOLDEN, &old.to_string(), IDENTITY, ISSUER).is_err());
    let other = include_bytes!("../tests/data/conda-attestation-rekor2.sigstore.json");
    let replacement = include_str!("../tests/data/staging-root.json");
    // A second real public upstream fixture requires its separate explicit
    // test root. This root is never part of production policy.
    assert!(verify_crypto(
        ARTIFACT,
        other,
        ROOTS,
        "jku@goto.fi",
        "https://github.com/login/oauth"
    )
    .is_err());
    verify_crypto(
        ARTIFACT,
        other,
        replacement,
        "jku@goto.fi",
        "https://github.com/login/oauth",
    )
    .unwrap();
    let mut removed: Value = serde_json::from_str(replacement).unwrap();
    removed["certificateAuthorities"] = json!([]);
    assert!(verify_crypto(
        ARTIFACT,
        other,
        &removed.to_string(),
        "jku@goto.fi",
        "https://github.com/login/oauth"
    )
    .is_err());
}
#[test]
fn bounds_refuse_malformed_and_excess_work_before_crypto() {
    let mutations: [fn(&mut Value); 13] = [
        |v| v["mediaType"] = json!("application/vnd.dev.sigstore.bundle+json;version=0.2"),
        |v| v["dsseEnvelope"]["signatures"] = json!([]),
        |v| {
            let s = v["dsseEnvelope"]["signatures"][0].clone();
            v["dsseEnvelope"]["signatures"] = json!([s.clone(), s]);
        },
        |v| v["dsseEnvelope"]["payloadType"] = json!("text/plain"),
        |v| v["dsseEnvelope"]["payload"] = json!(STANDARD.encode(vec![b' '; STATEMENT_LIMIT + 1])),
        |v| v["verificationMaterial"]["tlogEntries"] = json!([]),
        |v| {
            let e = v["verificationMaterial"]["tlogEntries"][0].clone();
            v["verificationMaterial"]["tlogEntries"] = json!(vec![e; 5]);
        },
        |v| {
            v["verificationMaterial"]["tlogEntries"][0]
                .as_object_mut()
                .unwrap()
                .remove("inclusionProof");
        },
        |v| {
            v["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["checkpoint"]
                ["envelope"] = json!("")
        },
        |v| {
            v["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["hashes"] =
                json!(vec!["AA=="; 65])
        },
        |v| {
            v["verificationMaterial"]["timestampVerificationData"]["rfc3161Timestamps"] =
                json!(vec![json!({"signedTimestamp":"AA=="}); 5])
        },
        |v| {
            let m = &mut v["verificationMaterial"];
            m.as_object_mut().unwrap().remove("certificate");
            m["publicKey"] = json!({"hint":"unsafe"});
        },
        |v| {
            let m = &mut v["verificationMaterial"];
            let c = m.as_object_mut().unwrap().remove("certificate").unwrap();
            m["x509CertificateChain"] = json!({"certificates":vec![c;5]});
        },
    ];
    for (i, mutate) in mutations.into_iter().enumerate() {
        assert!(bounded_bundle(&changed(mutate)).is_err(), "bound {i}");
    }
    assert!(bounded_bundle(&vec![b' '; BUNDLE_LIMIT + 1]).is_err());
    let duplicate = String::from_utf8(GOLDEN.to_vec()).unwrap().replacen(
        '{',
        "{\"mediaType\":\"duplicate\",",
        1,
    );
    assert!(bounded_bundle(duplicate.as_bytes()).is_err());
    let mut trailing = GOLDEN.to_vec();
    trailing.extend_from_slice(b" {}");
    assert!(bounded_bundle(&trailing).is_err());
}

#[test]
fn email_san_cannot_satisfy_same_value_uri_policy() {
    let bundle = include_bytes!("../tests/data/conda-attestation-rekor2.sigstore.json");
    let roots = include_str!("../tests/data/staging-root.json");
    let email = "jku@goto.fi";
    let issuer = "https://github.com/login/oauth";
    for identity in [
        IdentityMatcher::Exact(email.into()),
        IdentityMatcher::Email(email.into()),
    ] {
        let (result, _) = verify_crypto(ARTIFACT, bundle, roots, identity, issuer).unwrap();
        assert!(result.certificate_verified());
        assert!(result.sct_verified());
        assert!(result.tlog_verified());
        assert!(result.identity_policy_checked());
        assert!(!result.verified_timestamps().is_empty());
        assert!(
            matches!(result.identity(), Some(sigstore_crypto::SubjectAltName::Email(actual)) if actual == email)
        );
    }
    assert!(
        verify_crypto(
            ARTIFACT,
            bundle,
            roots,
            IdentityMatcher::Uri(email.into()),
            issuer
        )
        .is_err(),
        "an authenticated email SAN must not satisfy a URI policy with identical value bytes"
    );
}
