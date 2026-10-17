mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};
use support::*;

// A real signer with independently encoded SSH output. The SSH layer must
// consume this blob directly, without assuming a platform DER representation.
struct WireSigner {
    key: SoftSigner,
    corrupt: u8,
}

impl ssh::ExternalSigner for WireSigner {
    fn public_key(&self) -> Result<Vec<u8>, String> {
        Ok(self.key.public_wire())
    }

    fn sign_ssh(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        use p256::ecdsa::signature::Signer;
        let signature: p256::ecdsa::Signature = self.key.0.sign(data);
        let signature =
            ssh_key::Signature::try_from(&signature).map_err(|error| error.to_string())?;
        let mut blob =
            sshauth::record::encode_signature(&signature).map_err(|error| error.to_string())?;
        match self.corrupt {
            1 => blob = b"invalid signature".to_vec(),
            2 => blob.push(0),
            _ => {}
        }
        Ok(blob)
    }
}

fn login(corrupt: u8) -> Result<(), ssh::SshError> {
    let key = SoftSigner::random();
    let sshd = TestSshd::start(&[key.authorized_line()]);
    ssh::connect(
        params(&sshd, vec![wire_of(&sshd.host_public_key_line())]),
        ssh::SshAuthPlan::single(ssh::AuthMethod::Signer(Arc::new(WireSigner {
            key,
            corrupt,
        }))),
        Arc::new(knock::NoBind),
        Arc::new(NullEvents),
        &knock::Cancel::new(),
    )
    .map(|(connection, _)| connection.close())
}

#[test]
fn an_external_ssh_signature_authenticates() {
    let Some(()) = sshd_or_skip() else { return };
    login(0).expect("a standard SSH signature authenticates");
}

#[test]
fn malformed_external_signatures_fail_without_waiting_for_the_server() {
    let Some(()) = sshd_or_skip() else { return };
    for corrupt in [1, 2] {
        let start = Instant::now();
        let result = login(corrupt);
        assert!(
            matches!(result, Err(ssh::SshError::AuthFailed(_))),
            "{result:?}"
        );
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "invalid signer output must fail promptly"
        );
    }
}
