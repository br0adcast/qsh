//! The SSH RSA signature policy (#150): no RSA/SHA-1 (`ssh-rsa`) signature
//! in either direction, for every key source. The fake server verifies any
//! valid signature whatever it advertised, so these tests read what the
//! client asked for from a recording signer, the server's request counters
//! or OpenSSH's own refusal, never from a login's success alone.
mod support;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sshauth::prepared_key::{PreparedKey, RsaDigest};
use support::fake_server::{FakeAuth, FakeServer, ServerActivity};
use support::*;

fn fake_params(server: &FakeServer) -> ssh::SshParams {
    ssh::SshParams {
        host: "127.0.0.1".into(),
        port: server.port,
        username: "generated".into(),
        known_host_keys: vec![server.host_public_key_wire()],
        connect_timeout: Duration::from_secs(5),
        keepalive_interval: Duration::from_secs(15),
        compression: false,
        tcp_nodelay: true,
        knock: vec![],
    }
}

fn go(params: ssh::SshParams, methods: Vec<ssh::AuthMethod>) -> Result<(), ssh::SshError> {
    ssh::connect(
        params,
        ssh::SshAuthPlan {
            methods,
            prompter: Arc::new(ssh::NoPrompts),
        },
        Arc::new(knock::NoBind),
        Arc::new(NullEvents),
        &knock::Cancel::new(),
    )
    .map(|(connection, _)| connection.close())
}

/// A fake peer taking any key, with its request counters.
fn fake(auth: FakeAuth) -> (FakeServer, Arc<ServerActivity>) {
    let activity = Arc::new(ServerActivity::default());
    let server = FakeServer::start(FakeAuth {
        accept_any_key: true,
        activity: activity.clone(),
        ..auth
    });
    (server, activity)
}

/// An external RSA signer that signs with whatever algorithm it is asked
/// for, and records each request.
struct RecordingSigner {
    key: Arc<PreparedKey>,
    requested: Arc<Mutex<Vec<String>>>,
}

impl ssh::ExternalSigner for RecordingSigner {
    fn public_key(&self) -> Result<Vec<u8>, String> {
        self.key.public_key().to_bytes().map_err(|e| e.to_string())
    }
    fn sign_ssh(&self, _: &[u8]) -> Result<Vec<u8>, String> {
        Err("this RSA provider requires an explicit algorithm".into())
    }
    fn sign_ssh_with_algorithm(&self, data: &[u8], algorithm: &str) -> Result<Vec<u8>, String> {
        self.requested.lock().unwrap().push(algorithm.to_string());
        let digest = match algorithm {
            "ssh-rsa" => RsaDigest::Sha1,
            "rsa-sha2-256" => RsaDigest::Sha256,
            "rsa-sha2-512" => RsaDigest::Sha512,
            _ => return Err("unexpected signature algorithm".into()),
        };
        let signature = self.key.sign(data, digest).map_err(|e| e.to_string())?;
        sshauth::record::encode_signature(&signature).map_err(|e| e.to_string())
    }
}

struct RsaSources {
    _dir: tempfile::TempDir,
    file: std::path::PathBuf,
    key: Arc<PreparedKey>,
    agent: TestAgent,
}

fn rsa_sources() -> RsaSources {
    let dir = tempfile::tempdir().unwrap();
    let (file, _) = keygen_file("rsa", dir.path());
    let pem = std::fs::read_to_string(&file).unwrap();
    let key =
        Arc::new(PreparedKey::from_key(ssh_key::PrivateKey::from_openssh(&pem).unwrap()).unwrap());
    let agent = TestAgent::start();
    agent.add(&file);
    RsaSources {
        _dir: dir,
        file,
        key,
        agent,
    }
}

/// A peer whose best advertised RSA algorithm is legacy `ssh-rsa`: every RSA
/// source is skipped locally with the advertisement's reason. Nothing is
/// signed or even offered for it, and the login continues with the next
/// identity.
#[test]
fn a_legacy_only_rsa_advertisement_skips_every_rsa_source_without_signing() {
    let sources = rsa_sources();
    let keys = tempfile::tempdir().unwrap();
    let (ed25519, _) = keygen_file("ed25519", keys.path());
    for source in ["file", "pem", "agent", "external"] {
        let requested = Arc::new(Mutex::new(Vec::new()));
        let method = || match source {
            "file" => ssh::AuthMethod::KeyFile(sources.file.clone()),
            "pem" => ssh::AuthMethod::PrivateKeyPem(zeroize::Zeroizing::new(
                std::fs::read_to_string(&sources.file).unwrap(),
            )),
            "agent" => ssh::AuthMethod::Agent(sources.agent.socket()),
            _ => ssh::AuthMethod::Signer(Arc::new(RecordingSigner {
                key: sources.key.clone(),
                requested: requested.clone(),
            })),
        };
        let (server, activity) = fake(FakeAuth {
            rsa_hash: Some(None),
            ..Default::default()
        });
        match go(fake_params(&server), vec![method()]) {
            Err(ssh::SshError::AuthFailed(reason)) => assert!(
                reason.contains("only legacy ssh-rsa (SHA-1)"),
                "{source}: {reason}"
            ),
            other => panic!("{source}: expected a local skip, got {other:?}"),
        }
        // No public-key request, probe or signed, reached the server.
        assert_eq!(activity.userauth.load(Ordering::SeqCst), 0, "{source}");
        assert_eq!(
            activity.signed_publickey.load(Ordering::SeqCst),
            0,
            "{source}"
        );
        assert!(requested.lock().unwrap().is_empty(), "{source}");

        let (server, activity) = fake(FakeAuth {
            rsa_hash: Some(None),
            ..Default::default()
        });
        go(
            fake_params(&server),
            vec![method(), ssh::AuthMethod::KeyFile(ed25519.clone())],
        )
        .unwrap_or_else(|e| panic!("{source}: the next identity must log in: {e}"));
        assert_eq!(
            activity.signed_publickey.load(Ordering::SeqCst),
            1,
            "{source}"
        );
        assert!(requested.lock().unwrap().is_empty(), "{source}");
    }
}

/// A `server-sig-algs` list without any RSA entry -- indistinguishable, for
/// the client, from no list at all -- gets one SHA-512 offer, not SHA-1.
#[test]
fn an_advertisement_without_rsa_gets_one_sha512_offer() {
    let sources = rsa_sources();
    let (server, _) = fake(FakeAuth {
        advertise_no_rsa: true,
        ..Default::default()
    });
    let requested = Arc::new(Mutex::new(Vec::new()));
    go(
        fake_params(&server),
        vec![ssh::AuthMethod::Signer(Arc::new(RecordingSigner {
            key: sources.key.clone(),
            requested: requested.clone(),
        }))],
    )
    .unwrap();
    assert_eq!(*requested.lock().unwrap(), ["rsa-sha2-512"]);
}

/// OpenSSH offering only `ssh-rsa` host signatures: the handshake fails, and
/// the error says what the server's offer showed.
#[test]
fn a_legacy_only_rsa_host_signature_is_refused_with_the_servers_offer() {
    let Some(()) = sshd_or_skip() else { return };
    let keys = tempfile::tempdir().unwrap();
    let (ed25519, pub_line) = keygen_file("ed25519", keys.path());
    let sshd = TestSshd::start_with(SshdOptions {
        authorized_keys: vec![pub_line],
        host_key_types: vec!["rsa"],
        extra_config: vec!["HostKeyAlgorithms ssh-rsa".into()],
        ..SshdOptions::default()
    });
    let known = wire_of(&sshd.host_public_key_line_of("rsa"));
    match go(
        params(&sshd, vec![known]),
        vec![ssh::AuthMethod::KeyFile(ed25519)],
    ) {
        Err(ssh::SshError::Protocol(reason)) => {
            assert!(reason.contains("legacy ssh-rsa (SHA-1)"), "{reason}");
            assert!(reason.contains("offered: ssh-rsa"), "{reason}");
        }
        other => panic!(
            "expected a refused host-key negotiation, got {other:?}\n{}",
            sshd.log()
        ),
    }
}

/// OpenSSH default: an RSA host key is used through `rsa-sha2-512`, and file
/// and agent RSA keys sign with it, as sshd's own log records.
#[test]
fn rsa_keys_and_rsa_host_keys_keep_working_through_sha2() {
    let Some(()) = sshd_or_skip() else { return };
    let sources = rsa_sources();
    let public = std::fs::read_to_string(sources.file.with_extension("pub")).unwrap();
    for source in ["file", "agent"] {
        let sshd = TestSshd::start_with(SshdOptions {
            authorized_keys: vec![public.trim().to_string()],
            host_key_types: vec!["rsa"],
            extra_config: vec!["LogLevel DEBUG3".into()],
            ..SshdOptions::default()
        });
        let method = match source {
            "file" => ssh::AuthMethod::KeyFile(sources.file.clone()),
            _ => ssh::AuthMethod::Agent(sources.agent.socket()),
        };
        go(
            params(&sshd, vec![wire_of(&sshd.host_public_key_line_of("rsa"))]),
            vec![method],
        )
        .unwrap_or_else(|e| panic!("{source}: {e}\n{}", sshd.log()));
        // sshd's preauth child may write its last lines after the login
        // returned: wait, bounded, for the signed request's record.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut log = sshd.log();
        while !log.contains("authenticated 1 pkalg") && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
            log = sshd.log();
        }
        assert!(
            log.contains("kex: host key algorithm: rsa-sha2-512"),
            "{source}: {log}"
        );
        assert!(
            log.contains("authenticated 1 pkalg rsa-sha2-512"),
            "{source}: {log}"
        );
        assert!(!log.contains("pkalg ssh-rsa"), "{source}: {log}");
    }
}

/// An agent that answers a SHA-512 request with a valid signature of
/// another algorithm. russh refuses that reply, so it is never forwarded:
/// the fake server, which verifies any valid signature, never sees one.
/// qsh's agent path then sends an empty signature by design, which the
/// russh server cannot decode and ends the connection over; the login fails
/// either way.
#[test]
fn an_agent_reply_of_another_rsa_algorithm_is_not_forwarded() {
    let sources = rsa_sources();
    let agent = MismatchedAgent::start(sources.key.clone());
    let (server, activity) = fake(FakeAuth {
        rsa_hash: Some(Some(russh::keys::HashAlg::Sha512)),
        ..Default::default()
    });
    let result = go(
        fake_params(&server),
        vec![ssh::AuthMethod::Agent(agent.socket())],
    );
    assert!(result.is_err(), "{result:?}");
    assert_eq!(*agent.flags.lock().unwrap(), [4], "one SHA-512 request");
    assert_eq!(activity.signed_publickey.load(Ordering::SeqCst), 0);
}

/// A minimal SSH agent holding one RSA key, which always signs with legacy
/// `ssh-rsa`, whatever the request's flags ask for.
struct MismatchedAgent {
    dir: tempfile::TempDir,
    flags: Arc<Mutex<Vec<u32>>>,
}

impl MismatchedAgent {
    fn start(key: Arc<PreparedKey>) -> MismatchedAgent {
        use std::io::{Read, Write};
        let dir = tempfile::tempdir().unwrap();
        let listener =
            std::os::unix::net::UnixListener::bind(dir.path().join("agent.sock")).unwrap();
        let flags = Arc::new(Mutex::new(Vec::new()));
        let recorded = flags.clone();
        let blob = key.public_key().to_bytes().unwrap();
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let string = |bytes: &[u8]| {
                let mut out = (bytes.len() as u32).to_be_bytes().to_vec();
                out.extend_from_slice(bytes);
                out
            };
            loop {
                let mut len = [0; 4];
                if stream.read_exact(&mut len).is_err() {
                    return;
                }
                let mut message = vec![0; u32::from_be_bytes(len) as usize];
                if stream.read_exact(&mut message).is_err() {
                    return;
                }
                let reply = match message[0] {
                    // REQUEST_IDENTITIES -> IDENTITIES_ANSWER with one key.
                    11 => [
                        &[12][..],
                        &1u32.to_be_bytes(),
                        &string(&blob),
                        &string(b"rsa"),
                    ]
                    .concat(),
                    // SIGN_REQUEST -> SIGN_RESPONSE, always ssh-rsa.
                    13 => {
                        let mut at = 1;
                        let mut field = || {
                            let n = u32::from_be_bytes(message[at..at + 4].try_into().unwrap())
                                as usize;
                            let value = message[at + 4..at + 4 + n].to_vec();
                            at += 4 + n;
                            value
                        };
                        let _key = field();
                        let data = field();
                        recorded
                            .lock()
                            .unwrap()
                            .push(u32::from_be_bytes(message[at..at + 4].try_into().unwrap()));
                        let signature = key.sign(&data, RsaDigest::Sha1).unwrap();
                        let encoded = sshauth::record::encode_signature(&signature).unwrap();
                        [&[14][..], &string(&encoded)].concat()
                    }
                    _ => vec![5], // FAILURE
                };
                if stream.write_all(&string(&reply)).is_err() {
                    return;
                }
            }
        });
        MismatchedAgent { dir, flags }
    }

    fn socket(&self) -> std::path::PathBuf {
        self.dir.path().join("agent.sock")
    }
}
