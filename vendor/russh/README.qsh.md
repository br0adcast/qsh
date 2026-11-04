# qsh russh maintenance patch

This is the buildable source subset of crates.io `russh` **0.63.3**, from
<https://crates.io/api/v1/crates/russh/0.63.3/download>. Upstream is
<https://github.com/warp-tech/russh>; the published archive records commit
`f33baf439be8c59c49cb6cb2ae5976c579495bdf` and path `russh`. The SHA-256 of the
exact upstream `.crate` archive, also the checksum the lockfile recorded for it,
is:

```
036204edbd199552a5b3832f63c60dcdf395dc44c7f06b4af1c0e8139cc11bce
```

The upstream source and integration tests are retained. The archive has no
license file, so `LICENSE.txt` (Apache-2.0) is the repository's own at that
commit (Git blob `d645695673349e3947e8e5ae42332d0ac3164cd7`). The normalized
registry manifest has only the omitted README reference and the example and
benchmark targets removed. Upstream examples, benchmarks, README, lockfile and
registry metadata are omitted.

`qsh.patch` records the source/manifest changes relative to that archive. The
client verified the server's key-exchange signature by whatever algorithm the
signature named, without comparing it with the negotiated host-key algorithm.
With RSA/SHA-1 verification enabled by russh's own `ssh-key/sha1` feature, a
server could negotiate `rsa-sha2-512` and sign the exchange with `ssh-rsa`
(SHA-1), and the client accepted it. The client now refuses, as
`Error::WrongServerSig`, a signature whose algorithm differs from the
negotiated one. For a certificate host key that is the plain algorithm the
certificate contains, which `Names::key` already holds. qsh refuses RSA/SHA-1
on SSH (qsh #150). The latest release, 0.65.1, and upstream `main` at
`0681273687e8567ec6515f1ecca79517e1ded8d7` (2026-11-03) still verify without
this comparison. Drop the patch once a release contains an equivalent
check.

The workspace root selects this exact source with `[patch.crates-io]`. The
patch applies only while the dependents require exactly `=0.63.3`: a bump must
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
