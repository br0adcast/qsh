//! qsh-specific authorization and exact release wire formats.
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sigstore_crypto::FulcioCiClaims;
use std::collections::BTreeMap;

pub(crate) const REPOSITORY: &str = "https://github.com/br0adcast/qsh";
pub(crate) const ISSUER: &str = "https://token.actions.githubusercontent.com";
pub(crate) fn version(value: &str) -> Result<(), &'static str> {
    if value.len() > 128 || semver::Version::parse(value).is_err() {
        return Err("invalid release version");
    }
    Ok(())
}
pub(crate) fn identity(version: &str) -> String {
    format!("{REPOSITORY}/.github/workflows/release.yml@refs/tags/v{version}")
}
fn lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn optional_matches(value: &Option<String>, expected: &str) -> bool {
    value.as_deref().is_none_or(|v| v == expected)
}

// Only called with the CI claims returned by successful full certificate verification.
pub(crate) fn claims(version: &str, c: &FulcioCiClaims) -> Result<String, &'static str> {
    let reference = format!("refs/tags/v{version}");
    let commit = c
        .source_repository_digest
        .as_deref()
        .ok_or("missing source commit")?;
    if c.source_repository_uri.as_deref() != Some(REPOSITORY)
        || c.source_repository_identifier.as_deref() != Some("1423663657")
        || c.source_repository_ref.as_deref() != Some(reference.as_str())
        || c.source_repository_visibility_at_signing.as_deref() != Some("public")
        || !lower_hex(commit, 40)
        || !optional_matches(&c.build_signer_uri, &identity(version))
        || !optional_matches(&c.deprecated_github.workflow_repository, "br0adcast/qsh")
        || !optional_matches(&c.deprecated_github.workflow_sha, commit)
        || !optional_matches(&c.deprecated_github.workflow_ref, &reference)
    {
        return Err("release certificate claims do not match policy");
    }
    Ok(commit.to_owned())
}

fn products(version: &str) -> Vec<String> {
    let deb = match version.split_once('-') {
        Some((main, pre))
            if pre.chars().any(|c| c.is_ascii_digit())
                && pre.chars().any(|c| !c.is_ascii_digit()) =>
        {
            format!("{main}~{pre}")
        }
        _ => version.to_owned(),
    };
    // Match the pinned RPM generator and release assembly.
    let rpm = version.replace('-', "~");
    let mut names = Vec::with_capacity(12);
    for target in [
        "x86_64-unknown-linux-musl",
        "aarch64-unknown-linux-musl",
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
    ] {
        names.push(format!("qsh-{version}-{target}.tar.gz"));
    }
    for tool in ["qsh", "qshd"] {
        for arch in ["amd64", "arm64"] {
            names.push(format!("{tool}_{deb}-1_{arch}.deb"));
        }
        for arch in ["x86_64", "aarch64"] {
            names.push(format!("{tool}-{rpm}-1.{arch}.rpm"));
        }
    }
    names.sort();
    names
}
pub(crate) fn manifest(
    version_value: &str,
    bytes: &[u8],
) -> Result<BTreeMap<String, [u8; 32]>, &'static str> {
    version(version_value)?;
    if bytes.len() > crate::SUMS_LIMIT {
        return Err("manifest size limit");
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "invalid manifest")?;
    let lines: Vec<_> = text.split_inclusive('\n').collect();
    let names = products(version_value);
    if lines.len() != names.len() {
        return Err("manifest must list exactly twelve products");
    }
    let mut assets = BTreeMap::new();
    for (line, name) in lines.iter().zip(names) {
        let digest = line.get(..64).ok_or("invalid manifest hash")?;
        if !lower_hex(digest, 64) || line.get(64..) != Some(format!("  {name}\n").as_str()) {
            return Err("noncanonical release manifest");
        }
        let mut hash = [0; 32];
        for (i, byte) in hash.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&digest[i * 2..i * 2 + 2], 16)
                .map_err(|_| "invalid manifest hash")?;
        }
        assets.insert(name, hash);
    }
    Ok(assets)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Statement {
    #[serde(rename = "_type")]
    kind: String,
    subject: Vec<Subject>,
    #[serde(rename = "predicateType")]
    predicate_type: String,
    predicate: Predicate,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Subject {
    name: String,
    digest: SubjectDigest,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubjectDigest {
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Predicate {
    manifest_format: String,
    version: String,
    tag: String,
    source_commit: String,
}

pub(crate) fn statement(
    version: &str,
    manifest: &[u8],
    payload: &[u8],
    commit: &str,
) -> Result<(), &'static str> {
    if payload.len() > crate::STATEMENT_LIMIT {
        return Err("statement size limit");
    }
    crate::json::parse(payload)?;
    let s: Statement =
        serde_json::from_slice(payload).map_err(|_| "invalid qsh statement schema")?;
    let [subject] = s.subject.as_slice() else {
        return Err("statement must have exactly one subject");
    };
    if s.kind != "https://in-toto.io/Statement/v1"
        || subject.name != "SHA256SUMS"
        || subject.digest.sha256 != format!("{:x}", Sha256::digest(manifest))
        || s.predicate_type != "https://github.com/br0adcast/qsh/release-manifest/v1"
        || s.predicate.manifest_format != "qsh-sha256sums-v1"
        || s.predicate.version != version
        || s.predicate.tag != format!("v{version}")
        || !lower_hex(&s.predicate.source_commit, 40)
        || s.predicate.source_commit != commit
    {
        return Err("release statement does not bind the requested manifest");
    }
    Ok(())
}
