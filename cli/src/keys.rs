//! Which key to sign with, in which order.
//!
//! DELIBERATE DEVIATION from the order that looks obvious at first glance --
//! agent -> `-i` -> default files. An explicit `-i` goes FIRST here: it is a
//! direct instruction from the user, and an order in which it loses to the
//! agent makes the flag useless exactly when an agent is running, which is
//! most of the time. Without `-i`, the natural order stands: agent, then the
//! usual paths.
//!
//! The result is a LIST, not one signer. An agent commonly holds several
//! keys and the server accepts only the one in its `authorized_keys`, so the
//! client has to search the whole set rather than trust the first one
//! offered.
//!
//! An encrypted key found by the directory scan is passed over entirely when
//! the agent has already offered something to try -- not loaded, and above
//! all not prompted for. The common setup is an agent holding the very key
//! that also sits encrypted in `~/.ssh`, and prompting there asks for a
//! passphrase on EVERY launch, before the agent key that will work has even
//! been tried. The fallback, when the agent's keys are all refused and the
//! key that would work is the encrypted one on disk, is an explicit `-i`:
//! it wins over the agent outright and always prompts.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sshauth::agent::AgentSigner;
use sshauth::sign_file::FileSigner;
use transport::AuthSigner;

/// Asks for a passphrase. Separate from the decision so the decision is
/// testable; the real one reads the terminal with echo off.
pub trait Passphrase {
    fn ask(&self, prompt: &str) -> Option<String>;
}

/// Never answers: `--no-password` promises no question at all.
pub struct NeverAsk;

impl Passphrase for NeverAsk {
    fn ask(&self, _prompt: &str) -> Option<String> {
        None
    }
}

/// One thing worth trying, and how to name it in a message.
#[derive(Clone)]
pub struct Candidate {
    pub label: String,
    pub signer: Arc<dyn AuthSigner>,
}

// Manual, not derived: `Arc<dyn AuthSigner>` carries no `Debug` impl of its
// own, and the trait has no business growing one just so this struct can
// derive one -- `expect_err` in the tests below only needs the label.
impl fmt::Debug for Candidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Candidate")
            .field("label", &self.label)
            .finish()
    }
}

#[derive(Debug)]
pub enum KeyError {
    /// `-i` named something that could not be loaded.
    IdentityUnreadable { path: PathBuf, why: String },
    /// An encrypted key turned up in the directory scan while the agent had
    /// already offered candidates, so it was left alone rather than prompted
    /// for. Never produced for an explicit `-i`, which always prompts.
    Locked { path: PathBuf },
    /// Nothing to sign with, anywhere.
    NoKeys { looked: Vec<String> },
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::IdentityUnreadable { path, why } => {
                write!(f, "could not read key {}: {why}", path.display())
            }
            KeyError::Locked { path } => write!(
                f,
                "key is encrypted; not prompting for a passphrase while ssh-agent still \
                 has something to offer. Need this one specifically? Name it explicitly: -i {}",
                path.display()
            ),
            KeyError::NoKeys { looked } => write!(
                f,
                "no key found to sign with. Looked:\n  {}",
                looked.join("\n  ")
            ),
        }
    }
}

impl std::error::Error for KeyError {}

/// Everything worth trying, best first.
///
/// `login` is the account this run claims -- see `args::Args::login`. It
/// rides on every candidate returned here, not just the first tried: the
/// server checks the same account against whichever key ends up accepted.
pub fn candidates(
    identity: Option<&Path>,
    ask: &dyn Passphrase,
    login: &str,
) -> Result<Vec<Candidate>, KeyError> {
    let consult_agent = std::env::var_os("SSH_AUTH_SOCK").is_some();
    let ssh_dir = crate::paths::ssh_dir();
    candidates_in(identity, ask, consult_agent, ssh_dir.as_deref(), login)
}

/// The same, with the places to look handed in -- so a test does not depend
/// on the machine's home directory.
///
/// `consult_agent` only decides WHETHER an agent is worth trying at all; it
/// is never used to reach one. `AgentSigner::connect` always reads the real
/// `SSH_AUTH_SOCK` from the process environment (`sshauth::agent`), so there
/// is no way to hand this function a fake agent -- passing `true` here would
/// still dial whatever agent (if any) is actually configured on the machine
/// running the test. Every test below therefore passes `false`; the ordering
/// this function's own doc-comment promises is proven separately, against
/// `assemble`, with fake candidates that touch no I/O at all.
fn candidates_in(
    identity: Option<&Path>,
    ask: &dyn Passphrase,
    consult_agent: bool,
    ssh_dir: Option<&Path>,
    login: &str,
) -> Result<Vec<Candidate>, KeyError> {
    // An explicit key is an instruction: use it, and only it -- no agent
    // connection or directory scan is even attempted.
    if let Some(path) = identity {
        let (signer, print) = load_file(path, Some(ask), login)?;
        let explicit = Candidate {
            // The fingerprint belongs in the label because the "server did
            // not accept the key" message has to say WHICH key was
            // presented -- a path alone leaves the user comparing nothing
            // against their `authorized_keys`.
            label: format!("{} ({print})", path.display()),
            signer,
        };
        return Ok(assemble(Some(explicit), Vec::new(), Vec::new()));
    }

    let mut looked = Vec::new();
    let agent = if consult_agent {
        agent_candidates(&mut looked, login)
    } else {
        looked.push("ssh-agent: SSH_AUTH_SOCK not set".to_string());
        Vec::new()
    };
    let files = match ssh_dir {
        Some(ssh_dir) => file_candidates(
            ask,
            may_prompt_for_files(&agent),
            ssh_dir,
            &mut looked,
            login,
        ),
        None => {
            looked.push("~/.ssh: no home directory is known".to_string());
            Vec::new()
        }
    };

    let found = assemble(None, agent, files);
    if found.is_empty() {
        return Err(KeyError::NoKeys { looked });
    }
    Ok(found)
}

/// The ordering decision itself, and nothing else: no I/O happens here, so a
/// test can pin the deviation from the natural order -- and the plain order
/// below it -- without touching an agent, a file, or the environment. `explicit`
/// alone, when present, wins outright: `agent` and `files` are ignored even
/// if the caller happened to have gathered them (in practice `candidates_in`
/// never does, since gathering either is itself I/O worth skipping once an
/// explicit key is loaded). Without `explicit`, every agent candidate
/// precedes every file candidate.
fn assemble(
    explicit: Option<Candidate>,
    agent: Vec<Candidate>,
    files: Vec<Candidate>,
) -> Vec<Candidate> {
    if let Some(candidate) = explicit {
        return vec![candidate];
    }
    let mut found = agent;
    found.extend(files);
    found
}

/// Whether an encrypted key found on disk is worth asking a passphrase for.
///
/// It is not, once the agent has offered something: the usual setup is an
/// agent holding the very key that is also encrypted in `~/.ssh`, and
/// prompting there costs a passphrase on every launch for a key that is
/// never reached. The escape hatch is an explicit `-i`, which never comes
/// through here -- it wins over the agent outright and always prompts.
///
/// Only ENCRYPTED files are affected. An unencrypted key on disk still joins
/// the list behind the agent's, exactly as before: loading it asks the user
/// nothing.
fn may_prompt_for_files(agent: &[Candidate]) -> bool {
    agent.is_empty()
}

/// Everything the ssh-agent named by `SSH_AUTH_SOCK` currently offers, each
/// wrapped as its own candidate -- there can be several, and the server
/// accepts only the one in its `authorized_keys` (this module's own
/// doc-comment). Appends a message to `looked` for every failure along the
/// way, so the final "nothing worked" error can say where this looked.
fn agent_candidates(looked: &mut Vec<String>, login: &str) -> Vec<Candidate> {
    let mut found = Vec::new();
    match AgentSigner::connect() {
        Ok(agent) => match agent.identities() {
            Ok(keys) if !keys.is_empty() => {
                for key in keys {
                    let label = format!("ssh-agent: {}", sshauth::verify::fingerprint(&key));
                    // A fresh connection per key: `with_key` names which
                    // identity of the agent's set to sign with.
                    match AgentSigner::connect() {
                        Ok(signer) => found.push(Candidate {
                            label,
                            signer: Arc::new(signer.with_key(key).with_login(login.to_string())),
                        }),
                        Err(e) => looked.push(format!("ssh-agent: {e}")),
                    }
                }
            }
            Ok(_) => looked.push("ssh-agent: no keys".to_string()),
            Err(e) => looked.push(format!("ssh-agent: {e}")),
        },
        Err(e) => looked.push(format!("ssh-agent: {e}")),
    }
    found
}

/// The usual private key locations under `ssh_dir`, each wrapped as its own
/// candidate. Appends a message to `looked` for a file that is not there or
/// one that fails to load.
///
/// `may_prompt` decides what happens at an ENCRYPTED file: with it, the
/// passphrase is asked for as usual; without it, the file is passed over and
/// recorded in `looked`, and `ask` is never reached. See
/// [`may_prompt_for_files`] for why that is the right default when an agent
/// answered.
fn file_candidates(
    ask: &dyn Passphrase,
    may_prompt: bool,
    ssh_dir: &Path,
    looked: &mut Vec<String>,
    login: &str,
) -> Vec<Candidate> {
    let mut found = Vec::new();
    for name in ["id_ed25519", "id_ecdsa", "id_rsa"] {
        let path = ssh_dir.join(name);
        if !path.exists() {
            looked.push(format!("{} -- no such file", path.display()));
            continue;
        }
        match load_file(&path, may_prompt.then_some(ask), login) {
            Ok((signer, print)) => found.push(Candidate {
                label: format!("{} ({print})", path.display()),
                signer,
            }),
            Err(e) => looked.push(format!("{} -- {e}", path.display())),
        }
    }
    found
}

/// Loads a key file, asking for a passphrase only if the file turns out to
/// be encrypted -- prompting for a key that needs no passphrase trains people
/// to type one into anything that asks. Returns the signer and the key's
/// fingerprint, which the label needs.
///
/// `ask` is `None` when there is nobody to ask on this caller's behalf: an
/// encrypted file is then reported as [`KeyError::Locked`] instead of
/// prompting. Only the loader's typed PassphraseRequired result enters this
/// flow; unreadable, invalid and unsupported encrypted formats never ask.
fn load_file(
    path: &Path,
    ask: Option<&dyn Passphrase>,
    login: &str,
) -> Result<(Arc<dyn AuthSigner>, String), KeyError> {
    let loaded = match FileSigner::load_classified(path, None) {
        Ok(signer) => signer,
        Err(first) => {
            if !matches!(first, sshauth::keyfile::KeyFileError::PassphraseRequired) {
                return Err(KeyError::IdentityUnreadable {
                    path: path.to_path_buf(),
                    why: first.to_string(),
                });
            }
            let Some(ask) = ask else {
                return Err(KeyError::Locked {
                    path: path.to_path_buf(),
                });
            };
            let Some(phrase) = ask.ask(&format!("Passphrase for key {}: ", path.display())) else {
                return Err(KeyError::IdentityUnreadable {
                    path: path.to_path_buf(),
                    why: first.to_string(),
                });
            };
            FileSigner::load_classified(path, Some(&phrase)).map_err(|e| {
                KeyError::IdentityUnreadable {
                    path: path.to_path_buf(),
                    why: e.to_string(),
                }
            })?
        }
    };
    let print = sshauth::verify::fingerprint(loaded.public_key());
    let loaded = loaded.with_login(login.to_string());
    Ok((Arc::new(loaded), print))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use transport::{AuthError, AuthRecord};

    struct NoPassphrase;
    impl Passphrase for NoPassphrase {
        fn ask(&self, _prompt: &str) -> Option<String> {
            None
        }
    }

    struct Fixed(&'static str);
    impl Passphrase for Fixed {
        fn ask(&self, _prompt: &str) -> Option<String> {
            Some(self.0.to_string())
        }
    }

    /// Records whether it was ever asked, so a test can prove a passphrase
    /// prompt did NOT fire. `NoPassphrase` cannot do that job: it answers
    /// `None` regardless of whether `ask` was called at all, which is
    /// exactly why the "prompts on every failure" bug this guards against
    /// slipped past every earlier test.
    struct RecordingRefusal {
        asked: Cell<bool>,
    }

    impl RecordingRefusal {
        fn new() -> Self {
            RecordingRefusal {
                asked: Cell::new(false),
            }
        }
    }

    impl Passphrase for RecordingRefusal {
        fn ask(&self, _prompt: &str) -> Option<String> {
            self.asked.set(true);
            None
        }
    }

    /// A signer that is never actually asked to sign in these tests --
    /// `assemble` only ever looks at a `Candidate`'s label, never its
    /// signer. `transport::AuthSigner` has exactly one method, so this is
    /// the entire fake.
    struct StubSigner;
    impl AuthSigner for StubSigner {
        fn sign(
            &self,
            _handshake_hash: &[u8; 32],
            _nonce: Option<&[u8; transport::AUTH_NONCE_LEN]>,
        ) -> Result<AuthRecord, AuthError> {
            Err(AuthError::Backend("stub signer never signs".to_string()))
        }
    }

    fn fake_candidate(label: &str) -> Candidate {
        Candidate {
            label: label.to_string(),
            signer: Arc::new(StubSigner),
        }
    }

    fn write_encrypted_key(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
        let key = ssh_key::PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            ssh_key::Algorithm::Ed25519,
        )
        .expect("generate");
        let encrypted = key
            .encrypt(
                &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                "hunter2",
            )
            .expect("encrypt");
        let path = dir.join(name);
        std::fs::write(
            &path,
            encrypted
                .to_openssh(ssh_key::LineEnding::LF)
                .expect("encode")
                .as_bytes(),
        )
        .expect("write");
        path
    }

    fn write_key(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
        let key = ssh_key::PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            ssh_key::Algorithm::Ed25519,
        )
        .expect("generate");
        let path = dir.join(name);
        std::fs::write(
            &path,
            key.to_openssh(ssh_key::LineEnding::LF)
                .expect("encode")
                .as_bytes(),
        )
        .expect("write");
        path
    }

    /// An explicit `-i` is an instruction, so it comes first and it is the
    /// only candidate: the user named the key they mean.
    #[test]
    fn an_explicit_identity_is_the_only_candidate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_key(dir.path(), "id_test");
        let found = candidates(Some(&path), &NoPassphrase, "alice").expect("candidates");
        assert_eq!(found.len(), 1);
        assert!(
            found[0].label.contains("id_test"),
            "the label names the key, for the message when nothing works: {:?}",
            found[0].label
        );
    }

    /// The label carries the fingerprint, because the message for "the
    /// server accepted none of these" has to say WHICH key was presented --
    /// a path alone leaves the user with nothing to compare against their
    /// `authorized_keys`.
    #[test]
    fn a_label_carries_the_fingerprint_not_just_the_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_key(dir.path(), "id_test");
        let found = candidates(Some(&path), &NoPassphrase, "alice").expect("candidates");
        assert!(
            found[0].label.contains("SHA256:"),
            "the label must be comparable with authorized_keys: {:?}",
            found[0].label
        );
    }

    /// A path that is not there is worth its own message: a typo in `-i` is
    /// otherwise reported as "no suitable key", which sends the user looking
    /// in the wrong place.
    #[test]
    fn a_missing_explicit_identity_says_so() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("nope");
        let err = candidates(Some(&missing), &NoPassphrase, "alice").expect_err("must fail");
        assert!(
            matches!(err, KeyError::IdentityUnreadable { .. }),
            "{err:?}"
        );
        assert!(err.to_string().contains("nope"), "name the path: {err}");
    }

    /// A missing file is not an encrypted key. Prompting for a password
    /// before reporting "no such file" contradicts `load_file`'s own
    /// doc-comment and trains people to type a passphrase into anything
    /// that asks.
    #[test]
    fn a_missing_file_is_reported_without_asking_for_a_passphrase() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("nope");
        let ask = RecordingRefusal::new();
        let err = candidates(Some(&missing), &ask, "alice").expect_err("must fail");
        assert!(
            matches!(err, KeyError::IdentityUnreadable { .. }),
            "{err:?}"
        );
        assert!(
            !ask.asked.get(),
            "a missing file must be reported without ever asking for a passphrase"
        );
    }

    /// A file that does not parse as a private key at all (garbage bytes,
    /// or a public key) is not "encrypted" either -- the same guarantee as
    /// above, for the other kind of unreadable file.
    #[test]
    fn a_file_that_is_not_a_key_is_reported_without_asking_for_a_passphrase() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("garbage");
        std::fs::write(&path, b"this is not a key\n").expect("write");
        let ask = RecordingRefusal::new();
        let err = candidates(Some(&path), &ask, "alice").expect_err("must fail");
        assert!(
            matches!(err, KeyError::IdentityUnreadable { .. }),
            "{err:?}"
        );
        assert!(
            !ask.asked.get(),
            "a file that is not a key must be reported without ever asking for a passphrase"
        );
    }

    /// An encrypted key is asked about, once, and the answer is used.
    #[test]
    fn an_encrypted_key_is_unlocked_with_the_answer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_encrypted_key(dir.path(), "id_locked");

        let found = candidates(Some(&path), &Fixed("hunter2"), "alice").expect("unlocks");
        assert_eq!(found.len(), 1);
    }

    /// Refusing to type a passphrase is not a crash -- it is a user who
    /// changed their mind.
    #[test]
    fn declining_the_passphrase_reports_it_plainly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_encrypted_key(dir.path(), "id_locked");

        let err =
            candidates(Some(&path), &NoPassphrase, "alice").expect_err("no passphrase, no key");
        assert!(
            matches!(err, KeyError::IdentityUnreadable { .. }),
            "{err:?}"
        );
    }

    /// With no agent and no keys anywhere, the error lists where it looked --
    /// which is the difference between a user who can fix it and one who
    /// files a bug.
    #[test]
    fn nothing_anywhere_lists_where_it_looked() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = candidates_in(None, &NoPassphrase, false, Some(dir.path()), "alice")
            .expect_err("nothing to sign with");
        let message = err.to_string();
        assert!(matches!(err, KeyError::NoKeys { .. }), "{err:?}");
        assert!(
            message.contains("id_ed25519"),
            "list the paths tried: {message}"
        );
        assert!(
            message.contains("SSH_AUTH_SOCK"),
            "and the agent: {message}"
        );
    }

    /// Without a home directory there is no `~/.ssh` to scan, and the
    /// working directory is not scanned in its place.
    #[test]
    fn without_a_home_no_key_files_are_looked_for() {
        let err = candidates_in(None, &NoPassphrase, false, None, "alice")
            .expect_err("nothing to sign with");
        assert_eq!(
            err.to_string(),
            "no key found to sign with. Looked:\n  ssh-agent: SSH_AUTH_SOCK not set\n  \
             ~/.ssh: no home directory is known"
        );
    }

    /// The whole point: an explicit `-i` wins alone. `agent` and `files`
    /// are deliberately non-empty here, to prove they are ignored rather
    /// than merely happening to be empty.
    #[test]
    fn an_explicit_candidate_is_returned_alone_ignoring_the_other_sources() {
        let explicit = fake_candidate("explicit");
        let agent = vec![fake_candidate("agent-1")];
        let files = vec![fake_candidate("file-1")];
        let found = assemble(Some(explicit), agent, files);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].label, "explicit");
    }

    /// The natural agent-then-files order, sans the `-i` deviation this
    /// module documents: without an explicit identity, every agent candidate precedes every
    /// file candidate. A reorder or a dropped block here would pass no
    /// other test in this file.
    #[test]
    fn without_an_explicit_candidate_agent_candidates_precede_file_candidates() {
        let agent = vec![fake_candidate("agent-1"), fake_candidate("agent-2")];
        let files = vec![fake_candidate("file-1"), fake_candidate("file-2")];
        let found = assemble(None, agent, files);
        let labels: Vec<&str> = found.iter().map(|c| c.label.as_str()).collect();
        assert_eq!(labels, ["agent-1", "agent-2", "file-1", "file-2"]);
    }

    /// The setup this exists for: an agent holding the key, and that same
    /// key encrypted on disk. Prompting there asks for a passphrase on every
    /// launch, before the agent key that will actually work has even been
    /// tried -- so the encrypted file is passed over without the `Passphrase`
    /// seam ever being reached.
    #[test]
    fn an_encrypted_key_is_passed_over_when_the_agent_offered_something() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_encrypted_key(dir.path(), "id_ed25519");
        let ask = RecordingRefusal::new();
        let mut looked = Vec::new();

        let found = file_candidates(&ask, false, dir.path(), &mut looked, "alice");

        assert!(found.is_empty(), "an encrypted key is not a candidate here");
        assert!(
            !ask.asked.get(),
            "and nobody is asked for a passphrase that would go unused"
        );
        assert!(
            looked.iter().any(|l| l.contains("encrypted")),
            "the skip is still recorded, so \"nothing worked\" can say why: {looked:?}"
        );
    }

    /// With nothing else to try, the same file IS worth a passphrase: this
    /// is the user whose only key is the encrypted one on disk, and refusing
    /// to ask would leave them unable to connect at all.
    #[test]
    fn an_encrypted_key_is_still_offered_when_there_is_nothing_else() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_encrypted_key(dir.path(), "id_ed25519");
        let ask = Fixed("hunter2");
        let mut looked = Vec::new();

        let found = file_candidates(&ask, true, dir.path(), &mut looked, "alice");

        assert_eq!(found.len(), 1, "the key unlocks and joins the list");
    }

    /// The prompt really is asked for in that case -- proving the test above
    /// distinguishes "asked and answered" from "never asked".
    #[test]
    fn an_encrypted_key_prompts_when_prompting_is_allowed() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_encrypted_key(dir.path(), "id_ed25519");
        let ask = RecordingRefusal::new();
        let mut looked = Vec::new();

        let found = file_candidates(&ask, true, dir.path(), &mut looked, "alice");

        assert!(found.is_empty(), "the passphrase was refused");
        assert!(ask.asked.get(), "but it WAS asked for");
    }

    /// Only encrypted files are affected. An unencrypted key on disk still
    /// joins the list behind the agent's, exactly as before -- loading it
    /// asks the user nothing, so there is nothing to save them from.
    #[test]
    fn an_unencrypted_key_joins_the_list_even_when_the_agent_answered() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_key(dir.path(), "id_ed25519");
        let ask = RecordingRefusal::new();
        let mut looked = Vec::new();

        let found = file_candidates(&ask, false, dir.path(), &mut looked, "alice");

        assert_eq!(found.len(), 1);
        assert!(!ask.asked.get(), "an unencrypted key needs no passphrase");
    }

    /// The rule itself, named and pinned: the agent having anything at all
    /// is what turns the prompt off.
    #[test]
    fn the_agent_having_keys_turns_off_the_passphrase_prompt() {
        assert!(
            may_prompt_for_files(&[]),
            "with no agent candidates the disk is all there is"
        );
        assert!(
            !may_prompt_for_files(&[fake_candidate("agent-1")]),
            "with one to try, an encrypted file can wait for an explicit -i"
        );
    }

    /// An agent that answers but holds nothing must not swallow the file
    /// candidates that follow it in the order.
    #[test]
    fn an_empty_agent_list_still_yields_the_file_candidates() {
        let files = vec![fake_candidate("file-1")];
        let found = assemble(None, Vec::new(), files);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].label, "file-1");
    }
    #[test]
    fn an_encrypted_pkcs8_identity_is_unreadable_without_a_passphrase_prompt() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("encrypted-pkcs8");
        let key = ssh_key::PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        russh::keys::encode_pkcs8_pem_encrypted(
            &key,
            b"generated-fixture",
            1000,
            std::fs::File::create(&path).unwrap(),
        )
        .unwrap();
        let ask = RecordingRefusal::new();
        let error = candidates(Some(&path), &ask, "fixture").expect_err("unsupported encryption");
        assert!(matches!(error, KeyError::IdentityUnreadable { .. }));
        assert!(!ask.asked.get());
    }

    #[test]
    fn invalid_bytes_and_directory_identities_do_not_prompt_or_echo_input() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invalid");
        for bytes in [b"PRIVATE_INPUT_SENTINEL\x1b[2J".as_slice(), &[0xff, 0xfe]] {
            std::fs::write(&path, bytes).unwrap();
            let ask = RecordingRefusal::new();
            let error = candidates(Some(&path), &ask, "fixture").expect_err("invalid file");
            assert!(matches!(error, KeyError::IdentityUnreadable { .. }));
            assert!(!ask.asked.get());
            assert!(!error.to_string().contains("PRIVATE_INPUT_SENTINEL"));
            assert!(!error.to_string().contains('\x1b'));
        }
        let ask = RecordingRefusal::new();
        assert!(matches!(
            candidates(Some(dir.path()), &ask, "fixture"),
            Err(KeyError::IdentityUnreadable { .. })
        ));
        assert!(!ask.asked.get());
    }
}
