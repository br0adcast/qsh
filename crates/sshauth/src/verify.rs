//! Checking a client's proof against a user's `authorized_keys`.

use std::fs;
use std::path::PathBuf;

use ssh_key::authorized_keys::Entry;
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, PublicKey};
use transport::auth::{record_challenge, AuthError, AuthRecord, AuthVerifier, Principal};

use crate::record::{decode_public_key, decode_signature};

/// Verifies proofs against an `authorized_keys` file, re-read on every
/// attempt so a key added while the daemon runs takes effect at once.
pub struct AuthorizedKeysVerifier {
    path: PathBuf,
    uid: u32,
    name: String,
}

impl AuthorizedKeysVerifier {
    /// A verifier over the file at `path`, serving the account named by
    /// `uid`/`name` -- the one the daemon itself runs as. A version 2
    /// record's login is **not** checked against that name here: this
    /// daemon has exactly one account to offer, so a claim naming another
    /// selects nothing and refusing it would only break a client that
    /// guessed its own name differently. The system mode, where a name
    /// does select an account, checks it in the privileged helper.
    pub fn new(path: PathBuf, uid: u32, name: String) -> AuthorizedKeysVerifier {
        AuthorizedKeysVerifier { path, uid, name }
    }

    /// Whether `key` is authorized. Reads the file, then defers the actual
    /// parsing and matching to [`key_is_listed`] -- see that function's docs
    /// for why the two are split apart.
    fn is_authorized(&self, key: &PublicKey) -> Result<bool, AuthError> {
        let text = fs::read_to_string(&self.path)
            .map_err(|e| AuthError::Backend(format!("reading {}: {e}", self.path.display())))?;
        key_is_listed(&text, key)
    }
}

/// Whether `key` is listed in an `authorized_keys` file already read into
/// `text`. qsh uses the first line naming a key: a bare line authorizes it, a
/// line carrying options (`command=`/`from=`/`restrict`/...) refuses it
/// outright, and neither case keeps scanning for a laxer line further down
/// the file -- a key must not become more permissive than its first, most
/// specific listing.
///
/// Lines are walked ourselves (not via `AuthorizedKeys`'s iterator) because
/// a line that fails to parse still needs to be checked for this key's own
/// base64 blob, and the iterator throws the raw line away on a parse error.
/// Only whole-line comments are skipped. A `#` inside an option's quoted
/// value is part of the option, so both the parser and the fallback must
/// see the complete line. Truncating it could hide a restricted key from
/// the fallback and let a later bare listing authorize it.
///
/// Taking already-read text rather than a path is what lets this be the
/// ONE parser both modes share: the personal mode ([`AuthorizedKeysVerifier`],
/// above) reads the file itself and hands the text straight through; the
/// system mode's privileged helper reads its account's file under that
/// account's own switched identity (`qshd::helper::authorized`) and hands
/// the text here too. Two parsers would drift on options and key types --
/// this is the one place that decides "listed," full stop.
pub fn key_is_listed(text: &str, key: &PublicKey) -> Result<bool, AuthError> {
    let key_blob = key_blob(key)?;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match line.parse::<Entry>() {
            Ok(entry) if entry.public_key().key_data() == key.key_data() => {
                return Ok(entry.config_opts().is_empty());
            }
            Ok(_) => continue,
            Err(_) => {
                // ssh-key's authorized_keys parser only recognizes an
                // options prefix on a line that ALSO carries a trailing
                // comment (fewer than three total spaces makes it try,
                // and fail, to read the whole line as a bare key); a
                // `restrict ...` or `command="..." ...` line with
                // nothing after the key hard-errors here instead of
                // yielding an entry with populated config_opts. Rather
                // than build a second, heuristic options parser to
                // recognize that shape, we refuse unconditionally
                // whenever this key's own base64 blob shows up as a
                // token on any line we could not otherwise accept as a
                // bare entry -- a key must not become authorized just
                // because the one line naming it happened to be
                // unparseable. This is deliberately stricter than
                // OpenSSH, which would apply that line's options: we
                // cannot honor options at all, so refusing is the
                // only honest answer.
                if line.split_whitespace().any(|token| token == key_blob) {
                    return Ok(false);
                }
            }
        }
    }
    Ok(false)
}

/// The base64-encoded blob of `key`'s wire encoding -- the token that sits
/// between the algorithm name and the comment in an `authorized_keys` line.
fn key_blob(key: &PublicKey) -> Result<String, AuthError> {
    let openssh = key
        .to_openssh()
        .map_err(|e| AuthError::Backend(format!("encoding a key for comparison: {e}")))?;
    openssh
        .split_whitespace()
        .nth(1)
        .map(str::to_string)
        .ok_or_else(|| AuthError::Backend("encoded key has no base64 blob".to_string()))
}

/// What to do with a signature carrying a given algorithm.
enum AlgorithmDecision {
    /// Worth checking the signature bytes.
    Accepted,
    /// Refused on policy grounds (`ssh-rsa`, DSA, security keys, ...). This
    /// collapses into the same [`AuthError::BadSignature`] a wrong signature
    /// would produce, so a client learns nothing about which of the two it
    /// hit.
    Refused,
    /// A curve QSH does not support, even if another workspace consumer
    /// enables its crypto backend. Preserve the distinct Backend error
    /// rather than pretending that verification was attempted and failed.
    UnsupportedCurve(&'static str),
}

/// Classifies a signature's algorithm. `ssh-rsa` (RSA with SHA-1) is refused:
/// SHA-1 is broken for signatures, and every current OpenSSH offers
/// `rsa-sha2-256`/`rsa-sha2-512` instead. This checks the SIGNATURE's
/// algorithm, not the key's: an RSA key in `authorized_keys` is always
/// tagged `ssh-rsa` regardless of which hash a signature over it used, so
/// checking the key's own algorithm would make `rsa-sha2-256`/`-512`
/// unreachable.
fn classify_algorithm(algorithm: &Algorithm) -> AlgorithmDecision {
    match algorithm {
        Algorithm::Ed25519 => AlgorithmDecision::Accepted,
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256 | EcdsaCurve::NistP384,
        } => AlgorithmDecision::Accepted,
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP521,
        } => AlgorithmDecision::UnsupportedCurve("nistp521"),
        Algorithm::Rsa { hash: Some(_) } => AlgorithmDecision::Accepted,
        Algorithm::Rsa { hash: None } => AlgorithmDecision::Refused,
        _ => AlgorithmDecision::Refused,
    }
}

/// The local agent must obey the same accepted set as the remote verifier,
/// regardless of which algorithms a dependency feature union enables.
pub(crate) fn signature_algorithm_allowed(algorithm: &Algorithm) -> bool {
    matches!(classify_algorithm(algorithm), AlgorithmDecision::Accepted)
}

/// A key's OpenSSH SHA-256 fingerprint -- what goes in the log and in the
/// message a refused user sees.
pub fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

/// The short, uppercase key-family name `ssh-keygen -lf` prints in
/// parentheses after a fingerprint -- `ED25519`, `RSA`, `ECDSA`. This is
/// qshd's system-mode helper's `key <ALGORITHM>` field of the accept line
/// its design spec's §10 declares a contract, verified byte-for-byte
/// against a real `ssh-keygen -lf` (see this module's tests).
///
/// Taken from the key's OWN algorithm -- the same thing [`fingerprint`]
/// hashes -- never from a name a client sent in some separate field: a
/// client cannot make this string say anything a key of a different shape
/// would.
///
/// Only the three families [`verify_record_signature`]'s algorithm
/// allow-list ever admits (`Ed25519`, `Ecdsa`, `Rsa` with a hash) reach
/// this from that path in practice. The rest are covered anyway, both
/// because [`Algorithm`] is `#[non_exhaustive]` (a wildcard arm is
/// required to keep matching it at all) and because a function that only
/// half-knows its own answer should say so rather than panic.
pub fn algorithm_label(key: &PublicKey) -> &'static str {
    match key.algorithm() {
        Algorithm::Ed25519 => "ED25519",
        Algorithm::Rsa { .. } => "RSA",
        Algorithm::Ecdsa { .. } => "ECDSA",
        Algorithm::Dsa => "DSA",
        Algorithm::SkEd25519 => "ED25519-SK",
        Algorithm::SkEcdsaSha2NistP256 => "ECDSA-SK",
        _ => "UNKNOWN",
    }
}

/// Verify that `record`'s signature is a genuine signature, by SOME key,
/// over `record_challenge(handshake_hash, record)` -- applying the same
/// algorithm allow-list [`AuthorizedKeysVerifier::verify`] always has
/// (`ssh-rsa`/SHA-1, DSA and security keys refused; a curve unsupported by
/// QSH reported as [`AuthError::Backend`], not folded into
/// a bare signature failure). On success returns the parsed public key;
/// this function says nothing about whether that key is LISTED anywhere --
/// see [`key_is_listed`] for that, a separate question by design (checking
/// it here would leak, through timing, whether an unverified caller's key
/// happens to be listed).
///
/// Shared between [`AuthorizedKeysVerifier`] (personal mode, below) and
/// qshd's privileged helper (system mode), which builds its own
/// [`transport::auth::AuthRecord`] out of a `Request::Verify` and calls this
/// directly, so that the two modes cannot drift on what counts as a
/// verifying signature -- there must be exactly one implementation of this
/// check, not two that could quietly diverge.
pub fn verify_record_signature(
    handshake_hash: &[u8; 32],
    record: &AuthRecord,
) -> Result<PublicKey, AuthError> {
    let key = decode_public_key(&record.public_key)?;
    let signature = decode_signature(&record.signature)?;
    // `Signature::algorithm` hands back a value, not a reference.
    match classify_algorithm(&signature.algorithm()) {
        AlgorithmDecision::Accepted => {}
        AlgorithmDecision::Refused => return Err(AuthError::BadSignature),
        AlgorithmDecision::UnsupportedCurve(curve) => {
            return Err(AuthError::Backend(format!(
                "QSH does not support signatures using curve {curve}"
            )));
        }
    }
    signature::Verifier::verify(&key, &record_challenge(handshake_hash, record), &signature)
        .map_err(|_| AuthError::BadSignature)?;
    Ok(key)
}

impl AuthVerifier for AuthorizedKeysVerifier {
    /// `_login`: which device this handshake is for -- unused here. This
    /// verifier serves the personal mode, one account and no privileged
    /// helper to keep a per-device login table for, so nothing here cares.
    fn verify(
        &self,
        handshake_hash: &[u8; 32],
        record: &AuthRecord,
        _login: [u8; 16],
        _rhost: &str,
    ) -> Result<Principal, AuthError> {
        // Verify BEFORE consulting the file: an unverified key is just bytes
        // someone sent us, and matching it against the file first would leak
        // whether that key is listed. Verifying first stops a peer that
        // lacks the private key from learning whether that key is listed;
        // it does NOT stop an unauthenticated peer from causing a read --
        // anyone can present a genuine signature made with a key of their
        // own, and this function reads the file for every one of those,
        // listed or not.
        let key = verify_record_signature(handshake_hash, record)?;
        if !self.is_authorized(&key)? {
            return Err(AuthError::KeyNotAuthorized);
        }
        Ok(Principal {
            uid: self.uid,
            name: self.name.clone(),
            // The same string this function used to return outright: the
            // log line downstream prints it unchanged.
            identity: fingerprint(&key),
            // This verifier keeps nothing per login -- it re-reads
            // `authorized_keys` on every attempt and holds no entry that
            // could end -- so there are no incarnations to tell apart. A
            // server running it has no login-end reporter either, so
            // nothing ever compares the value.
            incarnation: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::{Algorithm, EcdsaCurve, PrivateKey};
    use std::io::Write;
    use transport::auth::{auth_challenge, auth_challenge_v2, AuthError, AuthV2, AuthVerifier};

    use crate::record::{encode_public_key, encode_signature};

    fn key() -> PrivateKey {
        PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("keygen")
    }

    fn record_for(key: &PrivateKey, hash: &[u8; 32]) -> transport::auth::AuthRecord {
        let sig = signature::Signer::try_sign(key, &auth_challenge(hash)).expect("sign");
        transport::auth::AuthRecord {
            public_key: crate::record::encode_public_key(key.public_key()).expect("encode"),
            signature: crate::record::encode_signature(&sig).expect("encode"),
            v2: None,
        }
    }

    fn write_authorized_keys_lines(lines: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("temp file");
        f.write_all(lines.as_bytes()).expect("write");
        f.flush().expect("flush");
        f
    }

    #[test]
    fn a_listed_key_with_a_good_signature_is_accepted() {
        let k = key();
        let file = write_authorized_keys_lines(&format!(
            "{} me@host\n",
            k.public_key().to_openssh().unwrap()
        ));
        let v = AuthorizedKeysVerifier::new(file.path().to_path_buf(), 1000, "test".to_string());
        let hash = [4u8; 32];
        let principal = v
            .verify(&hash, &record_for(&k, &hash), [0u8; 16], "")
            .expect("accepted");
        assert_eq!(
            principal.identity,
            fingerprint(k.public_key()),
            "the returned identity must be exactly this key's fingerprint, not merely fingerprint-shaped"
        );
    }

    #[test]
    fn a_signature_over_another_session_is_refused() {
        let k = key();
        let file =
            write_authorized_keys_lines(&format!("{}\n", k.public_key().to_openssh().unwrap()));
        let v = AuthorizedKeysVerifier::new(file.path().to_path_buf(), 1000, "test".to_string());
        let record = record_for(&k, &[1u8; 32]);
        assert_eq!(
            v.verify(&[2u8; 32], &record, [0u8; 16], ""),
            Err(AuthError::BadSignature)
        );
    }

    /// The trait's own doc-comments warn that a verifier which checks the
    /// bare hash would still interoperate with a signer making the same
    /// mistake, silently discarding the domain separation `auth_challenge`
    /// exists to provide. Varying only the hash (as the test above does)
    /// cannot catch that: it passes identically under a raw-hash
    /// implementation as long as signer and verifier agree. This test signs
    /// the raw hash directly and requires it to be refused.
    #[test]
    fn signing_the_raw_hash_instead_of_the_challenge_is_refused() {
        let k = key();
        let file =
            write_authorized_keys_lines(&format!("{}\n", k.public_key().to_openssh().unwrap()));
        let v = AuthorizedKeysVerifier::new(file.path().to_path_buf(), 1000, "test".to_string());
        let hash = [11u8; 32];
        let sig = signature::Signer::try_sign(&k, &hash).expect("sign the bare hash");
        let record = transport::auth::AuthRecord {
            public_key: crate::record::encode_public_key(k.public_key()).expect("encode"),
            signature: crate::record::encode_signature(&sig).expect("encode"),
            v2: None,
        };
        assert_eq!(
            v.verify(&hash, &record, [0u8; 16], ""),
            Err(AuthError::BadSignature)
        );
    }

    #[test]
    fn an_unlisted_key_is_refused_even_with_a_good_signature() {
        let listed = key();
        let stranger = key();
        let file = write_authorized_keys_lines(&format!(
            "{}\n",
            listed.public_key().to_openssh().unwrap()
        ));
        let v = AuthorizedKeysVerifier::new(file.path().to_path_buf(), 1000, "test".to_string());
        let hash = [3u8; 32];
        assert_eq!(
            v.verify(&hash, &record_for(&stranger, &hash), [0u8; 16], ""),
            Err(AuthError::KeyNotAuthorized)
        );
    }

    /// A line with options promises a restriction we cannot honor. Accepting
    /// the key while ignoring `command=`/`from=` would quietly weaken a setting
    /// someone made on purpose, so the key does not count as listed.
    #[test]
    fn a_line_with_options_does_not_authorize_its_key() {
        let k = key();
        let file = write_authorized_keys_lines(&format!(
            "command=\"backup\",no-pty {}\n",
            k.public_key().to_openssh().unwrap()
        ));
        let v = AuthorizedKeysVerifier::new(file.path().to_path_buf(), 1000, "test".to_string());
        let hash = [5u8; 32];
        assert_eq!(
            v.verify(&hash, &record_for(&k, &hash), [0u8; 16], ""),
            Err(AuthError::KeyNotAuthorized)
        );
    }

    /// qsh refuses a key whose first listing carries options, even if a
    /// later bare line lists the same key. This variant has a trailing
    /// comment on the restricted line, so ssh-key's own parser recognizes
    /// it as an entry with populated `config_opts` -- exercising the
    /// `Ok(entry) if key matches` branch of `is_authorized`. The no-comment
    /// shape (which that parser cannot represent as an entry at all) is
    /// covered separately below by
    /// `an_unparseable_options_line_still_blocks_a_later_bare_line_for_the_same_key`.
    #[test]
    fn an_options_line_for_a_key_is_not_overridden_by_a_later_bare_line() {
        let k = key();
        let openssh = k.public_key().to_openssh().unwrap();
        let file = write_authorized_keys_lines(&format!(
            "restrict,command=\"backup\" {openssh} restricted-copy\n{openssh} spare-copy\n"
        ));
        let v = AuthorizedKeysVerifier::new(file.path().to_path_buf(), 1000, "test".to_string());
        let hash = [12u8; 32];
        assert_eq!(
            v.verify(&hash, &record_for(&k, &hash), [0u8; 16], ""),
            Err(AuthError::KeyNotAuthorized),
            "the first (restricted) line for this key must win, not the later bare one"
        );
    }

    /// The shape discovered while writing the test above: ssh-key's
    /// `authorized_keys` parser only recognizes an options prefix on a line
    /// that ALSO carries a trailing comment (fewer than three total spaces
    /// makes it try, and fail, to read the whole line as a single bare
    /// key). A `restrict ...`/`command="..." ...` line with nothing after
    /// the key therefore hard-errors rather than yielding an entry with
    /// populated `config_opts` -- and without the blob-matching fallback in
    /// `is_authorized`, that error would be silently skipped, leaving a
    /// later bare line for the same key free to authorize it. This is
    /// deliberately stricter than OpenSSH (which would apply the
    /// restricted line's options): we cannot honor options at all, so
    /// refusing whenever this key's own blob appears on a line we could
    /// not otherwise parse is the only honest answer.
    #[test]
    fn an_unparseable_options_line_still_blocks_a_later_bare_line_for_the_same_key() {
        let k = key();
        let openssh = k.public_key().to_openssh().unwrap();
        let file = write_authorized_keys_lines(&format!(
            "restrict,command=\"backup\" {openssh}\n{openssh} spare-copy\n"
        ));
        let v = AuthorizedKeysVerifier::new(file.path().to_path_buf(), 1000, "test".to_string());
        let hash = [15u8; 32];
        assert_eq!(
            v.verify(&hash, &record_for(&k, &hash), [0u8; 16], ""),
            Err(AuthError::KeyNotAuthorized),
            "an unparseable line naming this key must block a later bare line for it"
        );
    }

    #[test]
    fn hashes_in_options_do_not_allow_a_later_bare_listing() {
        let k = key();
        let openssh = k.public_key().to_openssh().unwrap();
        for options in [
            "command=\"echo #x\"",
            "command=\"#x\"",
            "restrict,command=\"echo #x\",no-pty",
            "environment=\"NAME=#value\"",
        ] {
            for comment in ["", " restricted-copy"] {
                let restricted = format!("{options} {openssh}{comment}\n");
                assert!(!key_is_listed(&restricted, k.public_key()).unwrap());
                let text = format!("{restricted}{openssh} spare-copy\n");
                assert!(
                    !key_is_listed(&text, k.public_key()).unwrap(),
                    "a hash inside {options} must not hide the restricted listing"
                );
            }
        }
    }

    #[test]
    fn hash_comments_and_unrelated_restricted_keys_do_not_block_a_bare_key() {
        let k = key();
        let other = key();
        let openssh = k.public_key().to_openssh().unwrap();
        let unrelated = other.public_key().to_openssh().unwrap();
        let text = format!(
            "  # restrict {openssh}\n\t# {openssh}\n\n\
             command=\"echo #x\" {unrelated}\n\
             {openssh} user # trailing comment\n"
        );
        assert!(key_is_listed(&text, k.public_key()).unwrap());
        assert!(!key_is_listed(&format!(" # {openssh}\n"), k.public_key()).unwrap());
        assert!(!key_is_listed(&text, other.public_key()).unwrap());
    }

    #[test]
    fn a_missing_file_refuses_everyone_without_panicking() {
        let v = AuthorizedKeysVerifier::new(
            "/nonexistent/authorized_keys".into(),
            1000,
            "test".to_string(),
        );
        let k = key();
        let hash = [6u8; 32];
        assert!(matches!(
            v.verify(&hash, &record_for(&k, &hash), [0u8; 16], ""),
            Err(AuthError::Backend(_))
        ));
    }

    #[test]
    fn a_malformed_record_is_refused() {
        let file = write_authorized_keys_lines("");
        let v = AuthorizedKeysVerifier::new(file.path().to_path_buf(), 1000, "test".to_string());
        let bad = transport::auth::AuthRecord {
            public_key: vec![1, 2, 3],
            signature: vec![4, 5, 6],
            v2: None,
        };
        assert_eq!(
            v.verify(&[0u8; 32], &bad, [0u8; 16], ""),
            Err(AuthError::BadRecord)
        );
    }

    /// QSH refuses SHA-1 even when another consumer enables it in ssh-key.
    #[test]
    fn ssh_rsa_sha1_is_not_an_acceptable_signature_algorithm() {
        assert!(matches!(
            classify_algorithm(&Algorithm::Rsa { hash: None }),
            AlgorithmDecision::Refused
        ));
    }

    #[test]
    fn an_unrecognized_algorithm_is_not_acceptable() {
        assert!(matches!(
            classify_algorithm(&Algorithm::Dsa),
            AlgorithmDecision::Refused
        ));
    }

    /// An RSA key in `authorized_keys` is always written `ssh-rsa`
    /// (`PublicKey::algorithm()` returns `Rsa { hash: None }`
    /// unconditionally), while the *signature* carries whichever hash the
    /// client actually used. This is a full, real end-to-end acceptance
    /// test with a genuine RSA-2048 key and a genuine `rsa-sha2-256`
    /// PKCS#1v1.5 signature -- not a mock -- proving the accepted set
    /// reaches past whatever `ssh-key`'s own `Signer` impl happens to
    /// produce (which is always SHA-512, never SHA-256).
    #[test]
    fn an_rsa_sha2_256_signature_is_accepted() {
        use ssh_key::{private::RsaKeypair, public::KeyData, HashAlg};

        let pair = RsaKeypair::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            2048,
        )
        .expect("RSA fixture");
        let public_key = PublicKey::new(KeyData::Rsa(pair.public().clone()), "");
        let hash = [9u8; 32];
        let sig =
            signature::Signer::try_sign(&(&pair, Some(HashAlg::Sha256)), &auth_challenge(&hash))
                .expect("sign with upstream RSA conversion");

        let file = write_authorized_keys_lines(&format!("{}\n", public_key.to_openssh().unwrap()));
        let v = AuthorizedKeysVerifier::new(file.path().to_path_buf(), 1000, "test".to_string());
        let record = transport::auth::AuthRecord {
            public_key: crate::record::encode_public_key(&public_key).expect("encode"),
            signature: crate::record::encode_signature(&sig).expect("encode"),
            v2: None,
        };
        let principal = v
            .verify(&hash, &record, [0u8; 16], "")
            .expect("rsa-sha2-256 is accepted");
        assert_eq!(principal.identity, fingerprint(&public_key));
    }

    #[test]
    fn an_ecdsa_p256_signature_is_accepted() {
        let k = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
        )
        .expect("ecdsa keygen");
        let file =
            write_authorized_keys_lines(&format!("{}\n", k.public_key().to_openssh().unwrap()));
        let v = AuthorizedKeysVerifier::new(file.path().to_path_buf(), 1000, "test".to_string());
        let hash = [10u8; 32];
        let principal = v
            .verify(&hash, &record_for(&k, &hash), [0u8; 16], "")
            .expect("ecdsa p256 is accepted");
        assert_eq!(principal.identity, fingerprint(k.public_key()));
    }

    /// Unsupported P-521 remains a Backend error even when feature union
    /// enables its backend. Classification precedes cryptographic verification.
    #[test]
    fn a_p521_ecdsa_signature_is_refused_as_unsupported_not_as_bad() {
        use ssh_encoding::Encode;
        use ssh_key::public::{EcdsaPublicKey, KeyData};

        // SEC1 uncompressed point tag (0x04) followed by two 66-byte (P-521
        // field size) coordinates. `EcdsaPublicKey::from_sec1_bytes` only
        // checks this shape; classification below must refuse it before
        // any curve arithmetic, regardless of enabled dependency features.
        let mut point = vec![0x04u8];
        point.extend(std::iter::repeat_n(0u8, 2 * 66));
        let ecdsa_key = EcdsaPublicKey::from_sec1_bytes(&point).expect("sec1 point shape");
        let public_key = PublicKey::new(KeyData::Ecdsa(ecdsa_key), "");

        // Two SSH mpints encoding the value 1 (r = s = 1): shaped like a
        // real ECDSA signature blob, satisfying `Signature::new`'s size
        // check, without needing a signing operation for an unsupported curve. (An mpint encoding zero is rejected by
        // `as_positive_bytes` as "not positive", so 1 is the simplest value
        // that passes the shape check.)
        let one = ssh_key::Mpint::from_positive_bytes(&[1]);
        let mut sig_data = Vec::new();
        one.encode(&mut sig_data).expect("encode r");
        one.encode(&mut sig_data).expect("encode s");
        let signature = ssh_key::Signature::new(
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP521,
            },
            sig_data,
        )
        .expect("well-formed-shaped p521 signature");

        let file = write_authorized_keys_lines(&format!("{}\n", public_key.to_openssh().unwrap()));
        let v = AuthorizedKeysVerifier::new(file.path().to_path_buf(), 1000, "test".to_string());
        let record = transport::auth::AuthRecord {
            public_key: crate::record::encode_public_key(&public_key).expect("encode"),
            signature: crate::record::encode_signature(&signature).expect("encode"),
            v2: None,
        };
        assert!(
            matches!(
                v.verify(&[13u8; 32], &record, [0u8; 16], ""),
                Err(AuthError::Backend(_))
            ),
            "a P-521 signature must be refused as unsupported, not treated as a bad signature"
        );
    }

    /// Comments, blank lines, CRLF line endings, trailing whitespace and
    /// multi-word comments are exactly what an operator's real
    /// `authorized_keys` looks like. None of it should panic, and a
    /// legitimately listed key should still be recognized through all of it.
    #[test]
    fn realistic_authorized_keys_shapes_are_handled() {
        let k = key();
        let openssh = k.public_key().to_openssh().unwrap();
        let hash = [14u8; 32];
        let cases: &[(&str, String)] = &[
            ("bare key, no comment", format!("{openssh}\n")),
            (
                "blank lines and a comment line above the key",
                format!("\n# a comment\n\n{openssh}\n"),
            ),
            (
                "a multi-word trailing comment",
                format!("{openssh} several words of comment here\n"),
            ),
            ("CRLF line ending", format!("{openssh}\r\n")),
            (
                "trailing whitespace after the key",
                format!("{openssh}   \n"),
            ),
        ];
        for (label, contents) in cases {
            let file = write_authorized_keys_lines(contents);
            let v =
                AuthorizedKeysVerifier::new(file.path().to_path_buf(), 1000, "test".to_string());
            let principal = v
                .verify(&hash, &record_for(&k, &hash), [0u8; 16], "")
                .unwrap_or_else(|e| panic!("case: {label}: {e}"));
            assert_eq!(
                principal.identity,
                fingerprint(k.public_key()),
                "case: {label}"
            );
        }
    }

    /// Write `key`'s public half as a single bare `authorized_keys` line
    /// into `dir`, and return the file's path. The caller must keep `dir`
    /// alive for as long as the returned path is used.
    fn write_authorized_keys(dir: &std::path::Path, key: &PrivateKey) -> PathBuf {
        let path = dir.join("authorized_keys");
        fs::write(
            &path,
            format!("{}\n", key.public_key().to_openssh().unwrap()),
        )
        .expect("write authorized_keys");
        path
    }

    /// A version 2 record verifies over the version 2 challenge, and the
    /// principal names the account the daemon runs as -- not whatever the
    /// client claimed.
    #[test]
    fn a_v2_record_verifies_and_yields_the_daemons_own_account() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("keygen");
        let path = write_authorized_keys(dir.path(), &key);
        let verifier = AuthorizedKeysVerifier::new(path, 1000, "alice".to_string());

        let hash = [11u8; 32];
        let v2 = AuthV2 {
            login: "anyone".to_string(),
            nonce: [3u8; 16],
        };
        let sig = signature::Signer::try_sign(&key, &auth_challenge_v2(&hash, &v2)).expect("sign");
        let record = AuthRecord {
            public_key: encode_public_key(key.public_key()).expect("encode"),
            signature: encode_signature(&sig).expect("encode"),
            v2: Some(v2),
        };

        let principal = verifier
            .verify(&hash, &record, [0u8; 16], "")
            .expect("verifies");
        assert_eq!(principal.uid, 1000);
        assert_eq!(principal.name, "alice");
    }

    /// A version 2 record signed over the version 1 challenge is refused: the
    /// domains exist precisely so one cannot stand in for the other.
    #[test]
    fn a_v2_record_signed_over_the_v1_challenge_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("keygen");
        let path = write_authorized_keys(dir.path(), &key);
        let verifier = AuthorizedKeysVerifier::new(path, 1000, "alice".to_string());

        let hash = [11u8; 32];
        let sig = signature::Signer::try_sign(&key, &auth_challenge(&hash)).expect("sign");
        let record = AuthRecord {
            public_key: encode_public_key(key.public_key()).expect("encode"),
            signature: encode_signature(&sig).expect("encode"),
            v2: Some(AuthV2 {
                login: "anyone".to_string(),
                nonce: [3u8; 16],
            }),
        };

        assert_eq!(
            verifier.verify(&hash, &record, [0u8; 16], ""),
            Err(AuthError::BadSignature)
        );
    }

    /// A version 1 record still authenticates: this daemon serves one account,
    /// and a client built before version 2 existed must keep working.
    #[test]
    fn a_v1_record_still_verifies() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("keygen");
        let path = write_authorized_keys(dir.path(), &key);
        let verifier = AuthorizedKeysVerifier::new(path, 1000, "alice".to_string());

        let hash = [11u8; 32];
        let sig = signature::Signer::try_sign(&key, &auth_challenge(&hash)).expect("sign");
        let record = AuthRecord {
            public_key: encode_public_key(key.public_key()).expect("encode"),
            signature: encode_signature(&sig).expect("encode"),
            v2: None,
        };

        let principal = verifier
            .verify(&hash, &record, [0u8; 16], "")
            .expect("verifies");
        assert_eq!(principal.uid, 1000);
    }

    /// [`fingerprint`] and [`algorithm_label`], against real `ssh-keygen
    /// -lf` output -- not "a SHA-256 of something", the exact string
    /// OpenSSH's own tool prints.
    ///
    /// Recorded once, on this machine, from three real `ssh-keygen
    /// -t {ed25519,rsa,ecdsa} -b 256` keys, by running the real
    /// `ssh-keygen -lf` against each `.pub` file:
    ///
    /// ```text
    /// $ ssh-keygen -lf id_ed25519.pub
    /// 256 SHA256:cOT5me71o1Isd3udWjggALtTMy2XGgB13c75jGehkUQ test@fingerprint (ED25519)
    /// $ ssh-keygen -lf id_rsa.pub
    /// 2048 SHA256:EgLRa3C9ACQOSsSjcL+Qkh+5p4uy4veGIsCtb7BlmQs test@fingerprint (RSA)
    /// $ ssh-keygen -lf id_ecdsa.pub
    /// 256 SHA256:Pay/6YpQqHHdrfxtJNR/mwSN3ZzVGiS8rCzMrB8Jqlc test@fingerprint (ECDSA)
    /// ```
    ///
    /// Not re-derived by shelling out to `ssh-keygen` at test time: that
    /// would make this test depend on a binary the test environment may
    /// not have installed, and the point of a recorded comparison is that
    /// these bytes, once matched, never have to be re-matched to stay
    /// meaningful -- a future `ssh-key` upgrade that silently changed the
    /// fingerprint or the algorithm string would still be caught against
    /// the fixed answer above.
    #[test]
    fn fingerprint_and_algorithm_label_match_real_ssh_keygen_output() {
        let cases = [
            (
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKDahKO+JoO/ACS54FSEpTorgXzvrX/N/HoYCGBd/Dpc \
                 test@fingerprint",
                "SHA256:cOT5me71o1Isd3udWjggALtTMy2XGgB13c75jGehkUQ",
                "ED25519",
            ),
            (
                "ssh-rsa \
                 AAAAB3NzaC1yc2EAAAADAQABAAABAQDJB/HXSAEc8bNNLoLD1Qsu4f1g74JFUXUUeTUQSK0TSLCxIK0Onj3Uq5gamwRV9MHnnUbOLEqacdsJIZPw/iFmyqPSyZEOD+jHiasQgSBRZ0rA9buE8mGhvlAiGvPT4R2GSZM6eSc3+qd5QeD1pa0vegvu9wLuI+R8XJw/Lc+ThdsfAyYah2J/Qe5/5rIdbQo6phsZKIKfg32X/QVDeJ2CfxvuPtxzf+1qm9+da66Z+YJppVOtqb6P18AasRyp7uGU6fhOzdC5IZuRb18sOrPFl4/DF3Qi3QiTUuhDeChd83fbH2Zybae4KrptrHJVRBqT7qUT6nOlqQe2QWiUdse3 \
                 test@fingerprint",
                "SHA256:EgLRa3C9ACQOSsSjcL+Qkh+5p4uy4veGIsCtb7BlmQs",
                "RSA",
            ),
            (
                "ecdsa-sha2-nistp256 \
                 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHknTQNBjrBxi3k6C4tRHZ+qw9nQR/UaF0Lu2ljYDIIQtRpnn02NnvWNeiAAG/WE2z3OaDsW/32rycnZwpVBYvQ= \
                 test@fingerprint",
                "SHA256:Pay/6YpQqHHdrfxtJNR/mwSN3ZzVGiS8rCzMrB8Jqlc",
                "ECDSA",
            ),
        ];
        for (openssh_line, want_fingerprint, want_algorithm) in cases {
            let key =
                PublicKey::from_openssh(openssh_line).expect("parse a real OpenSSH public key");
            assert_eq!(
                fingerprint(&key),
                want_fingerprint,
                "must be byte-for-byte what `ssh-keygen -lf` printed for this key, not merely a \
                 SHA-256 of something"
            );
            assert_eq!(
                algorithm_label(&key),
                want_algorithm,
                "must be the family name `ssh-keygen -lf` prints in parentheses for this key"
            );
        }
    }
}
