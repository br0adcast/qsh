//! Offline authentication of qsh release metadata under a compiled trust policy.
//!
//! There is no network access, root refresh, trust override, or unsigned mode.
//! Historical signed evidence is checked at authenticated signing times; this
//! does not establish current revocation status or that a version is latest.
use sigstore_trust_root::TrustedRoot;
use sigstore_types::{Bundle, SignatureContent};
use sigstore_verify::{IdentityMatcher, VerificationPolicy, VerificationResult};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};
use x509_cert::der::Decode;

pub const SUMS_LIMIT: usize = 1024 * 1024;
pub const BUNDLE_LIMIT: usize = 256 * 1024;
pub const STATEMENT_LIMIT: usize = 16 * 1024;
const ROOTS: &str = include_str!("../roots/production.json");
mod contracts;
mod json;

/// A fixed diagnostic; never includes untrusted bundle contents or identities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(&'static str);
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Error {}

/// Evidence authenticated against this client's compiled release policy.
/// Private fields and no public constructor prevent checksum-only authority.
#[derive(Debug)]
pub struct VerifiedManifest {
    version: String,
    source_commit: String,
    assets: BTreeMap<String, [u8; 32]>,
    manifest: Vec<u8>,
    bundle: Vec<u8>,
}
impl VerifiedManifest {
    pub fn version(&self) -> &str {
        &self.version
    }
    pub fn source_commit(&self) -> &str {
        &self.source_commit
    }
    pub fn asset_hash(&self, basename: &str) -> Option<&[u8; 32]> {
        self.assets.get(basename)
    }
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest
    }
    pub fn bundle_bytes(&self) -> &[u8] {
        &self.bundle
    }
}

/// Authenticate the original manifest bytes and exact release statement.
/// Work is synchronous and bounded, so callers must check cancellation and
/// their remaining budget immediately before and after this call.
pub fn verify_manifest(
    version: &str,
    manifest: &[u8],
    bundle: &[u8],
) -> Result<VerifiedManifest, Error> {
    contracts::version(version).map_err(Error)?;
    if manifest.len() > SUMS_LIMIT {
        return Err(Error("manifest size limit"));
    }
    let (result, payload) = verify_crypto(
        manifest,
        bundle,
        ROOTS,
        IdentityMatcher::Uri(contracts::identity(version)),
        contracts::ISSUER,
    )
    .map_err(Error)?;
    let certificate = result
        .certificate()
        .ok_or(Error("missing verified certificate"))?;
    let commit = contracts::claims(version, &certificate.ci_claims).map_err(Error)?;
    contracts::statement(version, manifest, &payload, &commit).map_err(Error)?;
    let assets = contracts::manifest(version, manifest).map_err(Error)?;
    Ok(VerifiedManifest {
        version: version.to_owned(),
        source_commit: commit,
        assets,
        manifest: manifest.to_vec(),
        bundle: bundle.to_vec(),
    })
}

// The only trust-policy injection point is private, for public upstream fixtures.
fn verify_crypto(
    artifact: &[u8],
    bytes: &[u8],
    roots: &str,
    identity: impl Into<IdentityMatcher>,
    issuer: &str,
) -> Result<(VerificationResult, Vec<u8>), &'static str> {
    let bundle = bounded_bundle(bytes)?;
    let root = TrustedRoot::from_json(roots)
        .map_err(|_| "invalid embedded trust roots; update the client")?;
    let result = sigstore_verify::verify(artifact, &bundle, &VerificationPolicy::new(identity, issuer), &root)
        .map_err(|_| "release authentication failed; evidence or identity is invalid, or trust roots require a client update")?;
    if !result.certificate_verified()
        || !result.sct_verified()
        || !result.tlog_verified()
        || !result.identity_policy_checked()
        || result.verified_timestamps().is_empty()
    {
        return Err("incomplete release authentication");
    }
    // Fulcio's typed claim API returns one value per OID. Reject repeated
    // extension OIDs as well, rather than accepting an overwritten claim.
    let cert = bundle.signing_certificate().ok_or("certificate required")?;
    let cert = x509_cert::Certificate::from_der(cert.as_bytes())
        .map_err(|_| "invalid verified certificate")?;
    let mut oids = BTreeSet::new();
    for ext in cert.tbs_certificate.extensions.iter().flatten() {
        if !oids.insert(ext.extn_id) {
            return Err("conflicting certificate extensions");
        }
        if ["1.3.6.1.4.1.57264.1.1", "1.3.6.1.4.1.57264.1.8"]
            .contains(&ext.extn_id.to_string().as_str())
        {
            let bytes = ext.extn_value.as_bytes();
            let value = if let Ok(value) = x509_cert::der::asn1::Utf8StringRef::from_der(bytes) {
                value.as_str()
            } else {
                std::str::from_utf8(bytes).map_err(|_| "invalid verified issuer claim")?
            };
            if value != issuer {
                return Err("conflicting verified issuer claims");
            }
        }
    }
    let SignatureContent::DsseEnvelope(envelope) = &bundle.content else {
        return Err("DSSE bundle required");
    };
    Ok((result, envelope.payload.as_bytes().to_vec()))
}

fn bounded_bundle(bytes: &[u8]) -> Result<Bundle, &'static str> {
    if bytes.len() > BUNDLE_LIMIT {
        return Err("bundle size limit");
    }
    let value = json::parse(bytes)?;
    let object = value.as_object().ok_or("invalid bundle object")?;
    if object.len() != 3
        || !object.contains_key("verificationMaterial")
        || !object.contains_key("dsseEnvelope")
        || value["mediaType"] != "application/vnd.dev.sigstore.bundle.v0.3+json"
    {
        return Err("one Sigstore v0.3 DSSE bundle required");
    }
    let envelope = &value["dsseEnvelope"];
    if envelope["payloadType"] != "application/vnd.in-toto+json"
        || envelope["signatures"]
            .as_array()
            .is_none_or(|s| s.len() != 1)
    {
        return Err("one in-toto DSSE signature required");
    }
    if envelope["payload"]
        .as_str()
        .is_none_or(|s| s.len() > STATEMENT_LIMIT.div_ceil(3) * 4)
    {
        return Err("statement size limit");
    }
    let material = &value["verificationMaterial"];
    if material.get("publicKey").is_some() {
        return Err("certificate bundle required");
    }
    match (
        material.get("certificate"),
        material.get("x509CertificateChain"),
    ) {
        (Some(_), None) => {}
        (None, Some(chain))
            if chain["certificates"]
                .as_array()
                .is_some_and(|c| (1..=4).contains(&c.len())) => {}
        _ => return Err("certificate count limit"),
    }
    let entries = material["tlogEntries"]
        .as_array()
        .ok_or("transparency entries required")?;
    if !(1..=4).contains(&entries.len()) {
        return Err("transparency entry count limit");
    }
    for entry in entries {
        let proof = entry
            .get("inclusionProof")
            .ok_or("inclusion proof required")?;
        if proof["checkpoint"]["envelope"]
            .as_str()
            .is_none_or(str::is_empty)
            || proof
                .get("hashes")
                .is_some_and(|h| h.as_array().is_none_or(|a| a.len() > 64))
        {
            return Err("bounded proof and signed checkpoint required");
        }
    }
    if let Some(timestamps) = material.get("timestampVerificationData") {
        if !timestamps.is_object()
            || timestamps
                .get("rfc3161Timestamps")
                .is_some_and(|t| t.as_array().is_none_or(|a| a.len() > 4))
        {
            return Err("timestamp count limit");
        }
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "invalid bundle encoding")?;
    let bundle = Bundle::from_json(text).map_err(|_| "invalid Sigstore bundle")?;
    let SignatureContent::DsseEnvelope(envelope) = &bundle.content else {
        return Err("DSSE bundle required");
    };
    if envelope.payload.as_bytes().len() > STATEMENT_LIMIT {
        return Err("statement size limit");
    }
    json::parse(envelope.payload.as_bytes())?;
    // Rekor v1 bodies are embedded JSON. v2 uses a protobuf body instead.
    for (raw, entry) in entries
        .iter()
        .zip(&bundle.verification_material.tlog_entries)
    {
        if raw["kindVersion"]["version"] == "0.0.1" {
            json::parse(entry.canonicalized_body.as_bytes())?;
        }
    }
    Ok(bundle)
}
#[cfg(test)]
mod contract_tests;
#[cfg(test)]
mod tests;
