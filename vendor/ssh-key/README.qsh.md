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
notice. The last two files have documentation changes only. PPK specifies Ed25519's
private seed as an SSH mpint. The decoder previously counted the necessary
positive sign byte as part of a 32-byte seed, refusing canonical 33-byte
representations. It also accepted negative integers. After verifying the
original container MAC, the Ed25519 conversion now explicitly permits canonical
empty zero; otherwise it requires a positive magnitude, removes only its sign
byte, checks the magnitude is at most 32 bytes, and left-pads the original
seed in its existing zeroizing buffer. Global mpint canonicality, the PPK
parser and MAC calculation, ECDSA conversion and encrypted-key policy remain
unchanged.

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
generate synthetic seeds with boundary prefixes in memory, derive their
matching public keys, and verify identity and signatures through both OpenSSH
and PPK. They reject authenticated noncanonical, negative and overwidth
integers and independently tampered original MAC fields. No private fixture
is committed. The unrestricted random-key PPK test remains and now emits
canonical integers.

The crates.io index lists `0.7.0-rc.11` as the latest release. Upstream `master`
at `8deeb752f2bfb26bd47ed57a128b9a34d98a190b` still uses the affected
`e.as_bytes()` conversion. Remove this patch when a compatible upstream version
contains an equivalent correction, after running these boundary regressions.

The workspace root selects this exact source using `[patch.crates-io]` and
excludes it from workspace membership. Existing exact `=0.7.0-rc.11`
requirements and other lockfile versions are preserved. Patches apply only
from the consuming workspace root: downstream workspaces must carry their
own root patch. A version change must review the patch again; Cargo can
otherwise leave a patch unused with only a warning.
