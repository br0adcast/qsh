//! `authorized_keys` listing rules shared by tests and libFuzzer.
//!
//! One fixed, disposable public key is used so every input is compared
//! against a stable identity. The target never reads a user file, never
//! logs key material and never performs a signature operation.
use sshauth::verify::key_is_listed;

/// The largest text retained; larger authorization files are outside this
/// target and are separately bounded by the product reader.
pub const MAX_INPUT: usize = 8192;

/// A disposable Ed25519 public key, already present in the product's
/// fingerprint tests. Only the public half is used.
const PUBLIC_BLOB: [u8; 51] = [
    0x00, 0x00, 0x00, 0x0b, 0x73, 0x73, 0x68, 0x2d, 0x65, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x00,
    0x00, 0x00, 0x20, 0xa0, 0xda, 0x84, 0xa3, 0xbe, 0x26, 0x83, 0xbf, 0x00, 0x24, 0xb9, 0xe0, 0x54,
    0x84, 0xa5, 0x3a, 0x2b, 0x81, 0x7c, 0xef, 0xad, 0x7f, 0xcd, 0xfc, 0x7a, 0x18, 0x08, 0x60, 0x5d,
    0xfc, 0x3a, 0x5c,
];

const PUBLIC_LINE: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKDahKO+JoO/ACS54FSEpTorgXzvrX/N/HoYCGBd/Dpc test@fingerprint";

fn key() -> ssh_key::PublicKey {
    sshauth::record::decode_public_key(&PUBLIC_BLOB).expect("the fixed public key is valid")
}

/// Parse an arbitrary UTF-8 listing. Invalid UTF-8 is not a listing and is
/// outside this target; the product reader rejects it before this point.
pub fn exercise(input: &[u8]) {
    if input.len() > MAX_INPUT {
        return;
    }
    let Ok(text) = std::str::from_utf8(input) else {
        return;
    };
    let key = key();
    let first = key_is_listed(text, &key).expect("in-memory listing cannot fail");
    let second = key_is_listed(text, &key).expect("in-memory listing cannot fail");
    assert_eq!(first, second);
}

/// Synthetic listings. No real authorization file is read or embedded.
pub fn cases() -> Vec<(&'static str, Vec<u8>)> {
    let bare = format!("{PUBLIC_LINE}\n");
    let mut cases = vec![
        ("empty", Vec::new()),
        ("comment-only", b"# public keys\n".to_vec()),
        ("blank", b"\n\n".to_vec()),
        ("bare", bare.clone().into_bytes()),
        ("bare-no-newline", bare.trim_end().as_bytes().to_vec()),
        (
            "bare-with-leading-space",
            format!("  {PUBLIC_LINE}\n").into_bytes(),
        ),
        (
            "bare-crlf",
            format!("{PUBLIC_LINE}\r\n").into_bytes(),
        ),
        (
            "other-key",
            b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA other\n".to_vec(),
        ),
        (
            "command-with-comment",
            format!("command=\"echo ok\" {PUBLIC_LINE}\n").into_bytes(),
        ),
        (
            "command-without-comment",
            format!("command=\"echo ok\" {}\n", public_blob()).into_bytes(),
        ),
        (
            "restrict-with-comment",
            format!("restrict {PUBLIC_LINE}\n").into_bytes(),
        ),
        (
            "from-with-comment",
            format!("from=\"*.example.test\" {PUBLIC_LINE}\n").into_bytes(),
        ),
        (
            "options-then-bare",
            format!("restrict {PUBLIC_LINE}\n{PUBLIC_LINE}\n").into_bytes(),
        ),
        (
            "bare-then-options",
            format!("{PUBLIC_LINE}\nrestrict {PUBLIC_LINE}\n").into_bytes(),
        ),
        (
            "commented-key",
            format!("# {PUBLIC_LINE}\n").into_bytes(),
        ),
        (
            "malformed-line-containing-blob",
            format!("not-a-key {} extra\n", public_blob()).into_bytes(),
        ),
        (
            "quoted-hash",
            format!("command=\"echo # not a comment\" {PUBLIC_LINE}\n").into_bytes(),
        ),
        (
            "tab-separated",
            format!("ssh-ed25519\t{}\tcomment\n", public_blob()).into_bytes(),
        ),
    ];
    let junk = (0..=255u8).map(|i| b'a' + i % 26).collect();
    cases.push(("deterministic-junk", junk));
    cases
}

fn public_blob() -> &'static str {
    PUBLIC_LINE
        .split_whitespace()
        .nth(1)
        .expect("the fixed key has a blob")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listing_rules_are_explicit() {
        let key = key();
        assert!(key_is_listed(&format!("{PUBLIC_LINE}\n"), &key).unwrap());
        assert!(!key_is_listed(&format!("restrict {PUBLIC_LINE}\n"), &key).unwrap());
        assert!(!key_is_listed(&format!("command=\"echo ok\" {PUBLIC_LINE}\n"), &key).unwrap());
        assert!(!key_is_listed(&format!("# {PUBLIC_LINE}\n"), &key).unwrap());
        assert!(!key_is_listed("", &key).unwrap());
        // A restricted first listing cannot be relaxed by a later bare one.
        assert!(!key_is_listed(&format!("restrict {PUBLIC_LINE}\n{PUBLIC_LINE}\n"), &key).unwrap());
    }

    #[test]
    fn malformed_and_non_utf8_inputs_are_normal_inputs() {
        exercise(&[]);
        exercise(b"\xff\xfe");
        for len in 0..=512 {
            exercise(&vec![b'a'; len]);
        }
        exercise(&vec![b'a'; MAX_INPUT + 1]);
    }

    #[test]
    fn synthetic_corpus_matches_encoder_recipes_and_bounds() {
        let cases = cases();
        assert!(cases.len() <= 32);
        assert!(cases.iter().map(|(_, bytes)| bytes.len()).sum::<usize>() <= 256 * 1024);
        let directory =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus/authorized_keys");
        for (name, bytes) in cases {
            assert!(bytes.len() <= MAX_INPUT);
            assert_eq!(
                std::fs::read(directory.join(name)).unwrap(),
                bytes,
                "{name}"
            );
            exercise(&bytes);
        }
    }
}
