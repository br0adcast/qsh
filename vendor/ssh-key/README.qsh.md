# qsh ssh-key maintenance patch

This is the production source subset of crates.io `ssh-key` **0.7.0-rc.11**,
from <https://crates.io/api/v1/crates/ssh-key/0.7.0-rc.11/download>. Upstream is
<https://github.com/RustCrypto/SSH>; the published archive records commit
`7a1c757d2e2fcde32680e373d5226481de6d434e` and path `ssh-key`. The SHA-256 of the
exact upstream `.crate` archive, also its former lockfile checksum, is:

```
f9a32fae177b74a22aa9c5b01bf7e68b33545be32d9e381e248058d2adc15ce3
```

All 38 implementation source files and the required upstream README are
retained, together with both upstream licenses (Apache-2.0 OR MIT). Complete
inline private-key examples and fixed example passwords in `src/lib.rs` and
`src/private.rs` have been replaced by caller-parameterized documentation.
Their production code and feature gates are unchanged. Upstream integration
tests, private fixtures, examples, development dependencies, lockfile and
registry metadata are omitted. The normalized registry manifest
has only its omitted test targets and development dependencies removed. This
subset builds as a dependency; it is not an upstream test-suite distribution.
Upstream source unit tests and README examples may refer to omitted fixtures
or development dependencies. No cryptographic implementation modules or
feature definitions have been removed.

`qsh.patch` records the four changed upstream files: `Cargo.toml`,
`src/ppk.rs`, `src/lib.rs` and `src/private.rs`. Each carries a qsh modification
notice. The last two files have documentation changes only.

PuTTY's format documentation calls the Ed25519 private field an mpint, but PuTTY
writes the seed's little-endian integer as a plain SSH string: exactly 32 bytes
since 0.75 (`put_mp_le_fixedlen`), and 0.74 or earlier with its high-order zero
bytes trimmed (`put_mp_le_unsigned`). Its loader reads any such string as
unsigned little-endian. On disk the bytes are the OpenSSH seed unchanged.
Upstream decodes the field as an mpint. Its global canonicality check therefore
refuses a seed starting with `00` followed by a byte below `0x80`, and it
front-pads trimmed strings into a different seed. After verifying the original
container MAC, the Ed25519 conversion now reads the field as a string of at most
32 bytes into its existing zeroizing buffer, unchanged, with omitted trailing
bytes left zero. It then requires the seed to derive the container's public key,
as the OpenSSH keypair decoder already does. The PPK parser and MAC calculation,
RSA and ECDSA conversion and encrypted-key policy remain unchanged.

The maintenance file uses **GNU `diff -n` / RCS line edits**, not unified
diff and not `git apply` input. Its header names the pristine archive checksum
above, and each `# file:` section names an upstream-relative file. A `dN C`
record deletes C original lines starting at line N without storing their
contents. An `aN C` record inserts the following C literal lines after original
line N. Line numbers refer to the pristine file, not a progressively edited
copy. Deletions deliberately contain no removed private-key, seed or password
bytes. The file is a maintenance description; the build consumes the maintained
source directly and runs no patch installer.

To verify reconstruction, start from the exact checksum-verified archive,
interpret each section's records against that pristine file, and compare the
result byte for byte with the corresponding maintained file. All four results
were verified this way; the other 38 retained upstream files remain
byte-identical. Both licenses are unchanged. The source examples accept encoded
key material and passwords from callers rather than embedding private fixtures.

The deterministic regressions in `crates/sshauth/tests/key_file_formats.rs`
generate synthetic seeds with boundary prefixes and zero suffixes in memory,
serialize them in each PuTTY layout (v3, v2 and trimmed legacy v2), and verify
identity and signatures through both OpenSSH and PPK. A fixed set of seeds
derived from a public label must serialize byte for byte to the files that
official puttygen 0.85 and 0.74 releases write for them; only their SHA-256
digests are committed. The tests reject overwidth, truncated and sign-prefixed
fields, fields deriving a different public key, and independently tampered
original MAC fields. No private fixture is committed. The unrestricted
random-key PPK test remains and covers each layout.

The crates.io index lists `0.7.0-rc.11` as the latest release. Upstream `master`
at `8deeb752f2bfb26bd47ed57a128b9a34d98a190b` still decodes the field as an
mpint. Remove this patch when a compatible upstream version contains an
equivalent correction, after running these boundary regressions.

The workspace root selects this exact source using `[patch.crates-io]` and
excludes it from workspace membership. Existing exact `=0.7.0-rc.11`
requirements and other lockfile versions are preserved. Patches apply only
from the consuming workspace root: downstream workspaces must carry their
own root patch. A version change must review the patch again; Cargo can
otherwise leave a patch unused with only a warning.
