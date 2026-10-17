//! A minimal ssh-agent client: enough of draft-miller-ssh-agent to list keys
//! and ask for one signature.
//!
//! Written by hand rather than pulled in as a dependency: the protocol is
//! four message types, and doing it here keeps the RSA hash-algorithm flags
//! under our control -- an agent asked without them answers with a SHA-1
//! signature, which the server refuses.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use ssh_key::{Algorithm, PublicKey};
use transport::auth::{record_challenge, AuthError, AuthRecord, AuthSigner, AUTH_NONCE_LEN};

use crate::record::{decode_public_key, decode_signature, encode_public_key};

pub(crate) const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub(crate) const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub(crate) const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
pub(crate) const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

/// Ask an RSA key for a SHA-256 signature; without a flag the agent answers
/// with SHA-1, which we refuse on the other side.
const SSH_AGENT_RSA_SHA2_256: u32 = 2;

/// A frame larger than this is not a real agent reply -- it is either a
/// broken agent or a hostile one, and the fix is to refuse it before
/// allocating a buffer for it. The largest realistic reply (a handful of
/// RSA-8192 identities, or one signature) is a few kilobytes; this leaves
/// three orders of magnitude of headroom.
const MAX_AGENT_MESSAGE_LEN: usize = 1024 * 1024;

/// Signs through a running ssh-agent.
///
/// Opens a fresh connection for every request instead of holding one open.
/// ssh-agent's wire protocol carries no per-connection state, so a held
/// connection buys nothing but one saved `connect()` -- while costing a
/// lot. Agents get restarted or replaced under a live, long-running client
/// (`ssh-agent -k`, a re-login, a token-wrapper agent that closes each
/// connection itself, a forwarded-agent channel that closes with its SSH
/// session); after any of those a held connection is simply dead for the
/// rest of the process, with no path even recorded to reconnect. Worse:
/// `round_trip`'s own documented escape hatch for a stuck agent -- run it
/// on another thread with a timeout -- would be self-defeating over a
/// shared connection, since an abandoned thread blocked in `read_exact`
/// would hold the connection (and any lock guarding it) forever, wedging
/// every later call even after the agent recovers. OpenSSH's own agent
/// client opens the socket fresh per authentication attempt for the same
/// reasons.
pub struct AgentSigner {
    path: PathBuf,
    /// Which identity to sign with; `None` means "the agent's first key".
    key: Option<PublicKey>,
    /// The login name this signer claims. Required before a version 2
    /// record can be made.
    login: Option<String>,
}

impl AgentSigner {
    /// Connect to the agent named by `SSH_AUTH_SOCK`.
    pub fn connect() -> Result<AgentSigner, AuthError> {
        let path = agent_path(std::env::var_os("SSH_AUTH_SOCK"))?;
        AgentSigner::connect_at(&path)
    }

    /// Connect to the agent listening at `path`.
    pub fn connect_at(path: &Path) -> Result<AgentSigner, AuthError> {
        // Connect once up front so a missing or dead agent is reported now,
        // not buried inside the first real request; the connection itself
        // is not kept -- see this type's own doc comment for why.
        UnixStream::connect(path).map_err(|e| {
            AuthError::Backend(format!(
                "connecting to the ssh-agent at {}: {e}",
                path.display()
            ))
        })?;
        Ok(AgentSigner {
            path: path.to_path_buf(),
            key: None,
            login: None,
        })
    }

    /// Sign with this specific identity.
    pub fn with_key(mut self, key: PublicKey) -> AgentSigner {
        self.key = Some(key);
        self
    }

    /// The login name this signer claims. Required before a version 2
    /// record can be made.
    pub fn with_login(mut self, login: String) -> Self {
        self.login = Some(login);
        self
    }

    /// The identities the agent holds, in its own order. An entry this
    /// crate cannot parse (an attached certificate, say --
    /// `ssh-add` lists those alongside plain keys, and
    /// `PublicKey::from_bytes` does not understand the certificate wire
    /// format) is skipped rather than failing the whole list: one
    /// unrelated identity must not make every other key on the same agent
    /// unusable.
    pub fn identities(&self) -> Result<Vec<PublicKey>, AuthError> {
        let reply = self.round_trip(&[SSH_AGENTC_REQUEST_IDENTITIES])?;
        let mut rest = &reply[..];
        let kind = take_u8(&mut rest)?;
        if kind != SSH_AGENT_IDENTITIES_ANSWER {
            return Err(AuthError::Backend(format!("agent answered with {kind}")));
        }
        let count = take_u32(&mut rest)?;
        let mut keys = Vec::new();
        for _ in 0..count {
            let blob = take_string(&mut rest)?;
            let _comment = take_string(&mut rest)?;
            if let Ok(k) = decode_public_key(&blob) {
                keys.push(k);
            }
        }
        // Consistent with `record.rs`'s own strictness about trailing
        // bytes: a reply that does not end exactly where the declared
        // count says it should is a malformed agent reply, not something
        // to silently ignore the tail of.
        if !rest.is_empty() {
            return Err(AuthError::Backend(
                "agent reply has trailing bytes after the declared identity count".to_string(),
            ));
        }
        Ok(keys)
    }

    /// One request/response exchange, on its own fresh connection -- see
    /// this type's own doc comment for why no connection is held across
    /// calls.
    ///
    /// Deliberately sets no read timeout: a hardware-token-backed agent can
    /// block a SIGN_REQUEST for as long as the user takes to touch the
    /// token, which is routinely tens of seconds and has no natural upper
    /// bound -- the same reason `ssh`'s own agent client sets none. A
    /// genuinely wedged agent (accepts the connection, never answers) does
    /// therefore hang this call forever; callers that need a bound (a CLI
    /// wanting to show a spinner with a cancel key, say) can run it on its
    /// own thread, since `AgentSigner` is `Send + Sync`.
    fn round_trip(&self, payload: &[u8]) -> Result<Vec<u8>, AuthError> {
        let mut sock = UnixStream::connect(&self.path)
            .map_err(|e| AuthError::Backend(format!("connecting to the ssh-agent: {e}")))?;
        let mut framed = Vec::with_capacity(4 + payload.len());
        framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        framed.extend_from_slice(payload);
        sock.write_all(&framed)
            .map_err(|e| AuthError::Backend(format!("writing to the ssh-agent: {e}")))?;
        let mut len = [0u8; 4];
        sock.read_exact(&mut len)
            .map_err(|e| AuthError::Backend(format!("reading from the ssh-agent: {e}")))?;
        let len = u32::from_be_bytes(len) as usize;
        if len > MAX_AGENT_MESSAGE_LEN {
            return Err(AuthError::Backend(format!(
                "ssh-agent reply of {len} bytes exceeds the {MAX_AGENT_MESSAGE_LEN}-byte limit"
            )));
        }
        let mut body = vec![0u8; len];
        sock.read_exact(&mut body)
            .map_err(|e| AuthError::Backend(format!("reading from the ssh-agent: {e}")))?;
        Ok(body)
    }
}

/// Pure so it can be tested without touching the process environment:
/// mutating `SSH_AUTH_SOCK` in a test would race every sibling test's own
/// reads of the environment -- `set_var`/`remove_var` are unsound against
/// ANY concurrent access to the environment, not only to the same key, and
/// `tempfile::tempdir()` (used all over this file) reads `TMPDIR`.
fn agent_path(sock: Option<OsString>) -> Result<PathBuf, AuthError> {
    sock.map(PathBuf::from)
        .ok_or_else(|| AuthError::Backend("SSH_AUTH_SOCK is not set".to_string()))
}

fn take_u8(rest: &mut &[u8]) -> Result<u8, AuthError> {
    let (head, tail) = rest
        .split_first()
        .ok_or_else(|| AuthError::Backend("short agent reply".to_string()))?;
    *rest = tail;
    Ok(*head)
}

fn take_u32(rest: &mut &[u8]) -> Result<u32, AuthError> {
    if rest.len() < 4 {
        return Err(AuthError::Backend("short agent reply".to_string()));
    }
    let (head, tail) = rest.split_at(4);
    *rest = tail;
    Ok(u32::from_be_bytes(head.try_into().expect("four bytes")))
}

fn take_string(rest: &mut &[u8]) -> Result<Vec<u8>, AuthError> {
    let len = take_u32(rest)? as usize;
    if rest.len() < len {
        return Err(AuthError::Backend("short agent reply".to_string()));
    }
    let (head, tail) = rest.split_at(len);
    *rest = tail;
    Ok(head.to_vec())
}

impl AuthSigner for AgentSigner {
    fn sign(
        &self,
        handshake_hash: &[u8; 32],
        nonce: Option<&[u8; AUTH_NONCE_LEN]>,
    ) -> Result<AuthRecord, AuthError> {
        let key = match &self.key {
            Some(k) => k.clone(),
            None => self
                .identities()?
                .into_iter()
                .next()
                .ok_or_else(|| AuthError::Backend("the ssh-agent holds no keys".to_string()))?,
        };
        let key_blob = encode_public_key(&key)?;
        let v2 = crate::v2_fields(self.login.as_deref(), nonce)?;
        let mut record = AuthRecord {
            public_key: key_blob.clone(),
            signature: Vec::new(),
            v2,
        };
        let challenge = record_challenge(handshake_hash, &record);
        let flags = match key.algorithm() {
            Algorithm::Rsa { .. } => SSH_AGENT_RSA_SHA2_256,
            _ => 0,
        };

        let mut payload = vec![SSH_AGENTC_SIGN_REQUEST];
        payload.extend_from_slice(&(key_blob.len() as u32).to_be_bytes());
        payload.extend_from_slice(&key_blob);
        payload.extend_from_slice(&(challenge.len() as u32).to_be_bytes());
        payload.extend_from_slice(&challenge);
        payload.extend_from_slice(&flags.to_be_bytes());

        let reply = self.round_trip(&payload)?;
        let mut rest = &reply[..];
        let kind = take_u8(&mut rest)?;
        if kind != SSH_AGENT_SIGN_RESPONSE {
            return Err(AuthError::Backend(
                "the ssh-agent refused to sign (is the key still loaded?)".to_string(),
            ));
        }
        let signature = take_string(&mut rest)?;
        // A malformed reply here is the local agent misbehaving, not a
        // remote peer's bad record -- AuthError::BadRecord's own doc ties
        // it to bytes that came off the network, which these never did.
        // This is also where an agent that ignores the flags word (some
        // third-party ones do) and answers ssh-rsa/SHA-1 instead of the
        // requested rsa-sha2-256 gets caught: `Signature::decode` refuses
        // to build an `Rsa { hash: None }`-labeled value at all (see
        // `verify.rs`'s own note on the same quirk), so that reply fails
        // to parse right here.
        let sig = decode_signature(&signature).map_err(|_| {
            AuthError::Backend("the ssh-agent returned a malformed signature".to_string())
        })?;
        // Catch a signature that parses but does not actually verify --
        // made by the wrong key, or (for algorithms `decode_signature`
        // does accept in more than one hash variant) with a hash the
        // server would refuse -- locally, rather than letting it surface
        // only as the server's far-more-confusing `BadSignature`.
        signature::Verifier::verify(&key, &challenge, &sig).map_err(|_| {
            AuthError::Backend(
                "the ssh-agent returned a signature that does not verify against the requested key and challenge"
                    .to_string(),
            )
        })?;
        record.signature = signature;
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::{Algorithm, PrivateKey};
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::thread;
    use transport::auth::{auth_challenge, AuthSigner};

    /// Accepts connections until one delivers a full length-prefixed frame,
    /// silently absorbing connect-then-drop probes (like the one
    /// `connect_at` makes before every test's real call) along the way.
    /// Returns the still-open socket, for the caller to reply on, and the
    /// frame's body.
    fn accept_one_request(listener: &UnixListener) -> (UnixStream, Vec<u8>) {
        loop {
            let (mut sock, _) = listener.accept().expect("accept");
            let mut len = [0u8; 4];
            if sock.read_exact(&mut len).is_err() {
                continue;
            }
            let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
            sock.read_exact(&mut body).expect("body");
            return (sock, body);
        }
    }

    /// A stand-in agent: answers a REQUEST_IDENTITIES with `key`'s public
    /// half, then a SIGN_REQUEST with a real signature made by `key`, each
    /// on its own connection (mirroring `AgentSigner`'s own reconnect-per-
    /// request behavior), then exits.
    fn fake_agent(key: PrivateKey, path: std::path::PathBuf) -> thread::JoinHandle<Vec<u8>> {
        let listener = UnixListener::bind(&path).expect("bind");
        thread::spawn(move || loop {
            let (mut sock, body) = accept_one_request(&listener);
            match body[0] {
                SSH_AGENTC_REQUEST_IDENTITIES => {
                    let blob = crate::record::encode_public_key(key.public_key()).unwrap();
                    let mut payload = vec![SSH_AGENT_IDENTITIES_ANSWER];
                    payload.extend_from_slice(&1u32.to_be_bytes());
                    payload.extend_from_slice(&(blob.len() as u32).to_be_bytes());
                    payload.extend_from_slice(&blob);
                    payload.extend_from_slice(&0u32.to_be_bytes()); // empty comment
                    sock.write_all(&(payload.len() as u32).to_be_bytes())
                        .unwrap();
                    sock.write_all(&payload).unwrap();
                }
                SSH_AGENTC_SIGN_REQUEST => {
                    // body: type | string key | string data | uint32 flags
                    let key_len = u32::from_be_bytes(body[1..5].try_into().unwrap()) as usize;
                    let data_start = 5 + key_len + 4;
                    let data_len =
                        u32::from_be_bytes(body[5 + key_len..5 + key_len + 4].try_into().unwrap())
                            as usize;
                    let signed_data = body[data_start..data_start + data_len].to_vec();
                    let sig: ssh_key::Signature =
                        signature::Signer::try_sign(&key, &signed_data).unwrap();
                    let blob = crate::record::encode_signature(&sig).unwrap();
                    let mut payload = vec![SSH_AGENT_SIGN_RESPONSE];
                    payload.extend_from_slice(&(blob.len() as u32).to_be_bytes());
                    payload.extend_from_slice(&blob);
                    sock.write_all(&(payload.len() as u32).to_be_bytes())
                        .unwrap();
                    sock.write_all(&payload).unwrap();
                    return signed_data;
                }
                other => panic!("unexpected agent request {other}"),
            }
        })
    }

    #[test]
    fn the_agent_signs_the_challenge_and_the_verifier_accepts_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("agent.sock");
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let agent = fake_agent(key.clone(), sock_path.clone());

        let signer = AgentSigner::connect_at(&sock_path).expect("connect");
        let identities = signer.identities().expect("identities");
        assert_eq!(identities.len(), 1);
        let signer = signer.with_key(identities[0].clone());

        let hash = [12u8; 32];
        let record = signer.sign(&hash, None).expect("sign");

        // The agent signed exactly the domain-separated challenge.
        let signed = agent.join().expect("agent thread");
        assert_eq!(signed, auth_challenge(&hash));

        let mut authorized = tempfile::NamedTempFile::new().expect("temp file");
        std::io::Write::write_all(
            &mut authorized,
            format!("{}\n", key.public_key().to_openssh().unwrap()).as_bytes(),
        )
        .expect("write");
        std::io::Write::flush(&mut authorized).expect("flush");
        transport::auth::AuthVerifier::verify(
            &crate::verify::AuthorizedKeysVerifier::new(
                authorized.path().to_path_buf(),
                1000,
                "test".to_string(),
            ),
            &hash,
            &record,
            [0u8; 16],
            "",
        )
        .expect("the verifier accepts an agent-made proof");
    }

    #[test]
    fn a_missing_socket_reports_a_backend_error() {
        assert!(matches!(
            AgentSigner::connect_at(std::path::Path::new("/nonexistent/agent.sock")),
            Err(AuthError::Backend(_))
        ));
    }

    /// The happy-path test above always calls `with_key`. This exercises the
    /// other branch: no key named means "sign with whatever the agent hands
    /// back first" -- `sign` must itself issue a REQUEST_IDENTITIES.
    #[test]
    fn signing_without_with_key_uses_the_agents_only_identity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("agent.sock");
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let agent = fake_agent(key.clone(), sock_path.clone());

        let signer = AgentSigner::connect_at(&sock_path).expect("connect");
        let hash = [21u8; 32];
        let record = signer.sign(&hash, None).expect("sign");
        assert_eq!(
            record.public_key,
            crate::record::encode_public_key(key.public_key()).unwrap()
        );

        let signed = agent.join().expect("agent thread");
        assert_eq!(signed, auth_challenge(&hash));
    }

    /// With a login configured and a nonce from the server, the agent is
    /// asked to sign the version 2 challenge (not the version 1 one), and
    /// the resulting record carries the login and nonce under that
    /// signature.
    #[test]
    fn a_nonce_and_a_login_make_the_agent_sign_a_version_2_record() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("agent.sock");
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let agent = fake_agent(key.clone(), sock_path.clone());

        let signer = AgentSigner::connect_at(&sock_path)
            .expect("connect")
            .with_key(key.public_key().clone())
            .with_login("alice".to_string());

        let hash = [12u8; 32];
        let nonce = [4u8; 16];
        let record = signer.sign(&hash, Some(&nonce)).expect("sign");

        let v2 = record.v2.clone().expect("a nonce must produce a v2 record");
        assert_eq!(v2.login, "alice");
        assert_eq!(v2.nonce, nonce);

        // The agent was asked to sign the version 2 challenge, not the
        // version 1 one.
        let signed = agent.join().expect("agent thread");
        assert_eq!(signed, transport::auth::auth_challenge_v2(&hash, &v2));
    }

    /// Mirrors `sign_file`'s own pinning of this obligation: a nonce with no
    /// login configured must be refused, not silently downgraded to a
    /// version 1 record.
    #[test]
    fn an_agent_signer_refuses_a_nonce_without_a_login() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("agent.sock");
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519)
            .expect("keygen")
            .public_key()
            .clone();
        // Bound but never accepted from: `connect_at` only needs the socket
        // to exist to succeed, and (with `with_key` naming an identity so
        // `sign` skips its own `identities()` round trip) this signer must
        // reject the nonce before it would ever send a request to the
        // agent -- were it to try, this test would hang, since `AgentSigner`
        // deliberately sets no read timeout.
        let _listener = UnixListener::bind(&sock_path).expect("bind");

        let signer = AgentSigner::connect_at(&sock_path)
            .expect("connect")
            .with_key(key);
        assert!(matches!(
            signer.sign(&[21u8; 32], Some(&[4u8; 16])),
            Err(AuthError::Backend(_))
        ));
    }

    /// The wire-format proof that the SHA-2 flag is actually sent. Ed25519
    /// (used everywhere else in this file) always carries flags = 0, so a
    /// dropped or wrong flags word would be invisible to every other test
    /// here -- this is the one test that would notice.
    #[test]
    fn an_rsa_key_is_asked_for_a_sha2_256_signature() {
        use rsa::pkcs1v15::SigningKey;
        use rsa::RsaPrivateKey;
        use sha2::Sha256;
        use ssh_key::public::KeyData;
        use ssh_key::HashAlg;

        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("agent.sock");

        // Built via the `rsa` crate directly for the same reason
        // `verify.rs`'s RSA test is: `ssh_key::private::RsaKeypair::random`
        // is unusable for signing in this pinned ssh-key version. Unlike
        // the other RSA test in this file, this one signs for real (with a
        // genuine rsa-sha2-256 PKCS#1v1.5 signature over the actual
        // extracted challenge), so `sign`'s own local verification accepts
        // it and the test can go through the real public API instead of
        // reaching into private fields.
        let rsa_private = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("rsa keygen");
        let ssh_public: ssh_key::public::RsaPublicKey = (&rsa_private.to_public_key())
            .try_into()
            .expect("public key conversion");
        let rsa_key = PublicKey::new(KeyData::Rsa(ssh_public), "");

        let listener = UnixListener::bind(&sock_path).expect("bind");
        let agent = thread::spawn(move || {
            let (mut sock, body) = accept_one_request(&listener);
            assert_eq!(body[0], SSH_AGENTC_SIGN_REQUEST);
            let flags = u32::from_be_bytes(body[body.len() - 4..].try_into().unwrap());

            // body: type | string key | string data | uint32 flags
            let key_len = u32::from_be_bytes(body[1..5].try_into().unwrap()) as usize;
            let data_start = 5 + key_len + 4;
            let data_len =
                u32::from_be_bytes(body[5 + key_len..5 + key_len + 4].try_into().unwrap()) as usize;
            let signed_data = &body[data_start..data_start + data_len];

            let signing_key = SigningKey::<Sha256>::new(rsa_private);
            let raw_sig: rsa::pkcs1v15::Signature =
                signature::Signer::try_sign(&signing_key, signed_data).unwrap();
            let sig = ssh_key::Signature::new(
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha256),
                },
                signature::SignatureEncoding::to_vec(&raw_sig),
            )
            .expect("well-formed rsa-sha2-256 signature");
            let blob = crate::record::encode_signature(&sig).unwrap();
            let mut payload = vec![SSH_AGENT_SIGN_RESPONSE];
            payload.extend_from_slice(&(blob.len() as u32).to_be_bytes());
            payload.extend_from_slice(&blob);
            sock.write_all(&(payload.len() as u32).to_be_bytes())
                .unwrap();
            sock.write_all(&payload).unwrap();

            flags
        });

        let signer = AgentSigner::connect_at(&sock_path)
            .expect("connect")
            .with_key(rsa_key);
        signer.sign(&[1u8; 32], None).expect("sign");

        let flags = agent.join().expect("agent thread");
        assert_eq!(
            flags, SSH_AGENT_RSA_SHA2_256,
            "an RSA key must be asked for a SHA-2 signature -- the default (SHA-1) is refused by our verifier"
        );
    }

    #[test]
    fn an_agent_with_no_identities_reports_an_empty_list() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&sock_path).expect("bind");
        let agent = thread::spawn(move || {
            let (mut sock, body) = accept_one_request(&listener);
            assert_eq!(body[0], SSH_AGENTC_REQUEST_IDENTITIES);
            let payload = vec![SSH_AGENT_IDENTITIES_ANSWER, 0, 0, 0, 0]; // count = 0
            sock.write_all(&(payload.len() as u32).to_be_bytes())
                .unwrap();
            sock.write_all(&payload).unwrap();
        });

        let signer = AgentSigner::connect_at(&sock_path).expect("connect");
        assert_eq!(signer.identities().expect("identities"), Vec::new());
        agent.join().expect("agent thread");
    }

    #[test]
    fn signing_with_no_identities_and_no_with_key_is_reported() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&sock_path).expect("bind");
        let agent = thread::spawn(move || {
            let (mut sock, body) = accept_one_request(&listener);
            assert_eq!(body[0], SSH_AGENTC_REQUEST_IDENTITIES);
            let payload = vec![SSH_AGENT_IDENTITIES_ANSWER, 0, 0, 0, 0]; // count = 0
            sock.write_all(&(payload.len() as u32).to_be_bytes())
                .unwrap();
            sock.write_all(&payload).unwrap();
        });

        let signer = AgentSigner::connect_at(&sock_path).expect("connect");
        assert!(matches!(
            signer.sign(&[0u8; 32], None),
            Err(AuthError::Backend(_))
        ));
        agent.join().expect("agent thread");
    }

    /// Stands in for two distinct real-world cases that look identical on the
    /// wire: the agent explicitly refusing (`SSH_AGENT_FAILURE`, code 5 in the
    /// real protocol) and `with_key` naming a key the agent does not actually
    /// hold, which a real agent also answers with a failure rather than a
    /// signature. Either way, the client must report it, not panic on an
    /// unexpected message type.
    #[test]
    fn an_agent_refusal_is_reported_as_a_backend_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("agent.sock");
        let stray_key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519)
            .expect("keygen")
            .public_key()
            .clone();
        let listener = UnixListener::bind(&sock_path).expect("bind");
        let agent = thread::spawn(move || {
            let (mut sock, body) = accept_one_request(&listener);
            assert_eq!(body[0], SSH_AGENTC_SIGN_REQUEST);
            let payload = vec![5u8]; // SSH_AGENT_FAILURE
            sock.write_all(&(payload.len() as u32).to_be_bytes())
                .unwrap();
            sock.write_all(&payload).unwrap();
        });

        let signer = AgentSigner::connect_at(&sock_path)
            .expect("connect")
            .with_key(stray_key);
        assert!(matches!(
            signer.sign(&[0u8; 32], None),
            Err(AuthError::Backend(_))
        ));
        agent.join().expect("agent thread");
    }

    /// A hostile or simply broken agent can claim any length it likes before
    /// this client has seen a single byte of the actual reply.
    #[test]
    fn a_huge_declared_length_is_rejected_without_allocating() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&sock_path).expect("bind");
        let agent = thread::spawn(move || {
            let (mut sock, body) = accept_one_request(&listener);
            assert_eq!(body[0], SSH_AGENTC_REQUEST_IDENTITIES);
            // Far larger than any real agent message, and far larger than
            // what actually follows (nothing does).
            sock.write_all(&u32::MAX.to_be_bytes()).unwrap();
        });

        let signer = AgentSigner::connect_at(&sock_path).expect("connect");
        // Under Linux overcommit, `vec![0u8; len]` for a length this large
        // can succeed (by mapping zero pages) rather than failing outright,
        // in which case the subsequent read would hit EOF on the
        // never-sent body and produce the same `Err(Backend(_))` for an
        // unrelated reason. So this checks WHY it failed, not merely THAT
        // it failed -- otherwise a dropped size cap would go unnoticed.
        match signer.identities() {
            Err(AuthError::Backend(msg)) => assert!(
                msg.contains(&MAX_AGENT_MESSAGE_LEN.to_string()),
                "expected the error to name the {MAX_AGENT_MESSAGE_LEN}-byte limit, got: {msg}"
            ),
            other => panic!("expected a Backend error naming the size limit, got {other:?}"),
        }
        agent.join().expect("agent thread");
    }

    /// A reply that promises more bytes than the agent actually sends (a
    /// crash, or a connection cut mid-write) must surface as an error, not a
    /// panic in `read_exact`.
    #[test]
    fn a_truncated_reply_is_reported_not_panicked() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&sock_path).expect("bind");
        let agent = thread::spawn(move || {
            let (mut sock, body) = accept_one_request(&listener);
            assert_eq!(body[0], SSH_AGENTC_REQUEST_IDENTITIES);
            // Promise 100 bytes, then hang up after 10 -- as a crashed agent
            // process would.
            sock.write_all(&100u32.to_be_bytes()).unwrap();
            sock.write_all(&[0u8; 10]).unwrap();
        });

        let signer = AgentSigner::connect_at(&sock_path).expect("connect");
        assert!(matches!(signer.identities(), Err(AuthError::Backend(_))));
        agent.join().expect("agent thread");
    }

    #[test]
    fn agent_path_without_ssh_auth_sock_reports_a_backend_error() {
        assert!(matches!(agent_path(None), Err(AuthError::Backend(_))));
    }

    #[test]
    fn agent_path_with_ssh_auth_sock_uses_it() {
        let path = agent_path(Some(OsString::from("/tmp/example.sock"))).expect("path");
        assert_eq!(path, PathBuf::from("/tmp/example.sock"));
    }

    /// Stands in for a certificate `ssh-add` loaded alongside its key:
    /// agents list those in REQUEST_IDENTITIES too, and
    /// `PublicKey::from_bytes` does not understand the certificate wire
    /// format. One such entry must not take down the whole list.
    #[test]
    fn an_unparseable_identity_is_skipped_not_fatal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("agent.sock");
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let expected_key_data = key.public_key().key_data().clone();
        let listener = UnixListener::bind(&sock_path).expect("bind");
        let agent = thread::spawn(move || {
            let (mut sock, body) = accept_one_request(&listener);
            assert_eq!(body[0], SSH_AGENTC_REQUEST_IDENTITIES);
            let good_blob = crate::record::encode_public_key(key.public_key()).unwrap();
            let bad_blob: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02];
            let mut payload = vec![SSH_AGENT_IDENTITIES_ANSWER];
            payload.extend_from_slice(&2u32.to_be_bytes()); // count = 2
            payload.extend_from_slice(&(bad_blob.len() as u32).to_be_bytes());
            payload.extend_from_slice(&bad_blob);
            payload.extend_from_slice(&0u32.to_be_bytes()); // empty comment
            payload.extend_from_slice(&(good_blob.len() as u32).to_be_bytes());
            payload.extend_from_slice(&good_blob);
            payload.extend_from_slice(&0u32.to_be_bytes()); // empty comment
            sock.write_all(&(payload.len() as u32).to_be_bytes())
                .unwrap();
            sock.write_all(&payload).unwrap();
        });

        let signer = AgentSigner::connect_at(&sock_path).expect("connect");
        let identities = signer.identities().expect("identities");
        assert_eq!(
            identities.len(),
            1,
            "the unparseable entry must be skipped, leaving only the good key"
        );
        assert_eq!(identities[0].key_data(), &expected_key_data);
        agent.join().expect("agent thread");
    }

    /// Mirrors `record.rs`'s own insistence on rejecting trailing bytes: a
    /// reply that does not end exactly where the declared identity count
    /// says it should is malformed, not something to quietly truncate.
    #[test]
    fn trailing_bytes_after_the_declared_identity_count_are_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("agent.sock");
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let listener = UnixListener::bind(&sock_path).expect("bind");
        let agent = thread::spawn(move || {
            let (mut sock, body) = accept_one_request(&listener);
            assert_eq!(body[0], SSH_AGENTC_REQUEST_IDENTITIES);
            let blob = crate::record::encode_public_key(key.public_key()).unwrap();
            let mut payload = vec![SSH_AGENT_IDENTITIES_ANSWER];
            payload.extend_from_slice(&1u32.to_be_bytes()); // count = 1
            payload.extend_from_slice(&(blob.len() as u32).to_be_bytes());
            payload.extend_from_slice(&blob);
            payload.extend_from_slice(&0u32.to_be_bytes()); // empty comment
            payload.push(0xFF); // trailing garbage the count did not account for
            sock.write_all(&(payload.len() as u32).to_be_bytes())
                .unwrap();
            sock.write_all(&payload).unwrap();
        });

        let signer = AgentSigner::connect_at(&sock_path).expect("connect");
        assert!(matches!(signer.identities(), Err(AuthError::Backend(_))));
        agent.join().expect("agent thread");
    }

    #[test]
    fn an_unexpected_message_type_answering_identities_is_reported() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&sock_path).expect("bind");
        let agent = thread::spawn(move || {
            let (mut sock, body) = accept_one_request(&listener);
            assert_eq!(body[0], SSH_AGENTC_REQUEST_IDENTITIES);
            let payload = vec![5u8]; // SSH_AGENT_FAILURE, not an identities answer
            sock.write_all(&(payload.len() as u32).to_be_bytes())
                .unwrap();
            sock.write_all(&payload).unwrap();
        });

        let signer = AgentSigner::connect_at(&sock_path).expect("connect");
        assert!(matches!(signer.identities(), Err(AuthError::Backend(_))));
        agent.join().expect("agent thread");
    }

    /// An agent that ignores the flags word (some third-party ones do) and
    /// answers with, say, a SHA-1 signature must be caught here rather than
    /// only by the server's `BadSignature`, far from the cause. Simulated
    /// with a well-formed signature by the WRONG key, which is equally
    /// something `signature::Verifier::verify` catches and a naive
    /// "did it parse" check would not.
    #[test]
    fn a_signature_that_does_not_verify_is_reported_locally() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("agent.sock");
        let requested_key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519)
            .expect("keygen")
            .public_key()
            .clone();
        let wrong_key =
            PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");

        let listener = UnixListener::bind(&sock_path).expect("bind");
        let agent = thread::spawn(move || {
            let (mut sock, body) = accept_one_request(&listener);
            assert_eq!(body[0], SSH_AGENTC_SIGN_REQUEST);
            let sig: ssh_key::Signature =
                signature::Signer::try_sign(&wrong_key, b"not the challenge").unwrap();
            let blob = crate::record::encode_signature(&sig).unwrap();
            let mut payload = vec![SSH_AGENT_SIGN_RESPONSE];
            payload.extend_from_slice(&(blob.len() as u32).to_be_bytes());
            payload.extend_from_slice(&blob);
            sock.write_all(&(payload.len() as u32).to_be_bytes())
                .unwrap();
            sock.write_all(&payload).unwrap();
        });

        let signer = AgentSigner::connect_at(&sock_path)
            .expect("connect")
            .with_key(requested_key);
        assert!(matches!(
            signer.sign(&[3u8; 32], None),
            Err(AuthError::Backend(_))
        ));
        agent.join().expect("agent thread");
    }

    /// The actual real-world case behind the "verify locally" checks
    /// above: an agent that ignores the SHA-2 flag and answers with the
    /// legacy ssh-rsa/SHA-1 tag. This must not reach the caller as a usable
    /// record -- the server refuses ssh-rsa outright, and a `BadSignature`
    /// there would leave the real cause (an agent quietly answering the
    /// wrong way) invisible.
    #[test]
    fn an_agent_answering_with_the_legacy_ssh_rsa_tag_is_reported_locally() {
        use rsa::RsaPrivateKey;
        use ssh_key::public::KeyData;

        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("agent.sock");

        let rsa_private = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("rsa keygen");
        let ssh_public: ssh_key::public::RsaPublicKey = (&rsa_private.to_public_key())
            .try_into()
            .expect("public key conversion");
        let rsa_key = PublicKey::new(KeyData::Rsa(ssh_public), "");

        let listener = UnixListener::bind(&sock_path).expect("bind");
        let agent = thread::spawn(move || {
            let (mut sock, body) = accept_one_request(&listener);
            assert_eq!(body[0], SSH_AGENTC_SIGN_REQUEST);
            // A hand-built "ssh-rsa" (SHA-1) signature blob: string
            // algorithm name, string signature bytes. The signature
            // content does not matter -- this must fail before any crypto
            // is even attempted.
            let mut sig_bytes = Vec::new();
            let name = b"ssh-rsa";
            sig_bytes.extend_from_slice(&(name.len() as u32).to_be_bytes());
            sig_bytes.extend_from_slice(name);
            let junk = vec![0u8; 256];
            sig_bytes.extend_from_slice(&(junk.len() as u32).to_be_bytes());
            sig_bytes.extend_from_slice(&junk);

            let mut payload = vec![SSH_AGENT_SIGN_RESPONSE];
            payload.extend_from_slice(&(sig_bytes.len() as u32).to_be_bytes());
            payload.extend_from_slice(&sig_bytes);
            sock.write_all(&(payload.len() as u32).to_be_bytes())
                .unwrap();
            sock.write_all(&payload).unwrap();
        });

        let signer = AgentSigner::connect_at(&sock_path)
            .expect("connect")
            .with_key(rsa_key);
        assert!(matches!(
            signer.sign(&[9u8; 32], None),
            Err(AuthError::Backend(_))
        ));
        agent.join().expect("agent thread");
    }

    /// Distinguishes "the local agent misbehaved" from "a remote peer sent
    /// a bad record": `AuthError::BadRecord`'s own doc ties it to bytes
    /// that came off the network, which a local agent's reply never did.
    #[test]
    fn a_malformed_signature_from_the_agent_is_a_backend_error_not_a_bad_record() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("agent.sock");
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519)
            .expect("keygen")
            .public_key()
            .clone();
        let listener = UnixListener::bind(&sock_path).expect("bind");
        let agent = thread::spawn(move || {
            let (mut sock, body) = accept_one_request(&listener);
            assert_eq!(body[0], SSH_AGENTC_SIGN_REQUEST);
            let payload = vec![SSH_AGENT_SIGN_RESPONSE, 0, 0, 0, 3, 1, 2, 3]; // bogus signature bytes
            sock.write_all(&(payload.len() as u32).to_be_bytes())
                .unwrap();
            sock.write_all(&payload).unwrap();
        });

        let signer = AgentSigner::connect_at(&sock_path)
            .expect("connect")
            .with_key(key);
        assert!(matches!(
            signer.sign(&[0u8; 32], None),
            Err(AuthError::Backend(_))
        ));
        agent.join().expect("agent thread");
    }
}
