# qsh russh maintenance patch

This is the buildable source subset of crates.io `russh` **0.65.2**, from
<https://crates.io/api/v1/crates/russh/0.65.2/download>. Upstream is
<https://github.com/Eugeny/russh>; the published archive records commit
`56a999871aa134072e4f2a7395fe2de313870e21` and path `russh`. The SHA-256 of the
exact upstream `.crate` archive matches the published registry checksum:

```
78229f06e4d96d83bea5f5133ad3b6e4b5f0ce22d8e31c1ff7243ec8e18d5ba1
```

All 15 published integration-test files and the production source are retained.
The archive has no license file, so `LICENSE.txt` (Apache-2.0) is the
repository's own at that commit (Git blob
`d645695673349e3947e8e5ae42332d0ac3164cd7`). The normalized registry manifest
has only the omitted README reference and example and benchmark targets
removed. Upstream examples, benchmarks, README, lockfile and registry metadata
are omitted.

Fixed private-key constants and the upstream tests that depend on their exact
encodings are omitted from `src/helpers.rs`, `src/keys/mod.rs`, and
`src/keys/format/tests.rs`. The module documentation accepts caller-provided
key material and passwords. Public-key tests, generated-key tests and
synthetic malformed-input tests remain. Agent tests use fresh Ed25519/RSA keys
instead of decoding fixed fixtures; their behavioral assertions remain.
The omitted upstream coverage includes feature-disabled RSA signing, fixed
OpenSSH/encrypted key formats, RFC 8410 forms, named and explicit EC domain
parameters, and exact PKCS#8 re-encoding. These omissions are not test passes.
qsh's own generated-key format/native tests remain separate qualification.

`qsh.patch` records five changed files: `Cargo.toml`, `src/client/kex.rs`,
`src/helpers.rs`, `src/keys/mod.rs`, and `src/keys/format/tests.rs`. Each carries
a qsh modification notice. It uses **GNU `diff -n` / RCS line edits**, not
unified diff or `git apply` input. Each `# file:` section names an
upstream-relative file. A `dN C` record deletes C pristine lines starting at N
without storing their contents; an `aN C` record inserts the following C lines
after pristine line N. Deletions contain no removed private-key bytes.
Reconstruction against the checksum-verified archive was compared byte for
byte for all five files; the other 70 retained archive files are unchanged.
The build consumes the maintained source directly and runs no patch installer.

The client verified the server's key-exchange signature by whatever algorithm the
signature named, without comparing it with the negotiated host-key algorithm.
With RSA/SHA-1 verification enabled by russh's own `ssh-key/sha1` feature, a
server could negotiate `rsa-sha2-512` and sign the exchange with `ssh-rsa`
(SHA-1), and the client accepted it. The client now refuses, as
`Error::WrongServerSig`, a signature whose algorithm differs from the
negotiated one. For a certificate host key that is the plain algorithm the
certificate contains, which `Names::key` already holds. qsh refuses RSA/SHA-1
on SSH (qsh #150). The published 0.65.2 release and upstream snapshot
`56a999871aa134072e4f2a7395fe2de313870e21`, reviewed on 2026-11-17,
still verify without this comparison. Retain the guard until a released
version contains an equivalent check.

The upgrade removes upstream's optional `legacy-ed25519-pkcs8-parser`
fallback, which qsh did not enable. The enabled PKCS#8 path continues through
the main decoder. The new upstream authentication tests use generated keys
and synthetic protocol fixtures; they do not contain private-key fixtures or
credentials for a real account. Omitted examples and external fixture files
remain outside this source subset.

The workspace root selects this exact source with `[patch.crates-io]`. The
patch applies only while the dependents require exactly `=0.65.2`: a bump must
redo it, or Cargo stops using it with only a warning. qsh's
`rsa_policy::a_host_signature_of_another_algorithm_than_negotiated_is_refused`
fails without the patch. Cargo patches apply only from the consuming workspace
root; downstream workspaces must carry the patch explicitly. Keep it minimal
and recheck it against upstream on dependency upgrades.

Validation, from a copy outside the workspace with the archive's `Cargo.lock`:

```sh
cargo test --locked --no-default-features --features flate2,ring,rsa
cargo tree -i russh
```

The `keys::load_public_key` doctest reads `../files/id_ed25519.pub` from the
upstream repository, which is outside the published archive, and fails in such
a copy.
