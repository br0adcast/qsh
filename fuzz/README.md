# Parser fuzzing for qsh

This isolated workspace exercises the public parsers that consume untrusted
bytes. It is not part of the product workspace, does not change product
dependencies or the supported compiler, and never opens a network connection
or reads a user configuration file.

The ordinary tests and libFuzzer targets share the same properties. The seeds
are generated from public encoders and contain no recorded traffic, host names,
keys, session data or user paths.

## Targets

| Target | Input | Limit | Checked property |
| --- | --- | --- | --- |
| `channel_codec` | one kind byte plus a channel payload | 65,537 B | Successful client/server decode survives canonical encode/decode with semantic equality; the envelope deframes to exactly one bounded record. |
| `handshake_payload` | raw msg1 or msg2 payload | 512 B | A successful parse survives canonical re-encoding. Accepted extension tails and absent compatibility fields are compared semantically, not by original byte equality. |
| `wire_datagram` | full datagram, or a fixed handshake body | 2,048 B | A successful frame survives re-encoding. Key offers, cookie replies and cookie-wrapped msg1 bodies round-trip. |
| `deframer` | raw control or shell record stream | 4,096 B | Feeding the same stream in several chunkings produces the same records, overflow state, buffered tail and sticky shell error. Decoded shell records re-encode exactly. |
| `authorized_keys` | UTF-8 `authorized_keys` text | 8,192 B | Listing decisions are deterministic; ordinary tests pin bare, commented, restricted and malformed lines against one fixed public key. Invalid UTF-8 is outside this parser's boundary. |
| `terminal_feed_resize` | four geometry bytes plus terminal input | 8,196 B | The real emulator accepts arbitrary feed/resize splits without panic, and the returned frame dimensions agree with the model after resizing. |

The channel target checks the public channel decoders. The deframer target
checks the record envelope separately; it is not a second channel parser. The
terminal target checks robustness and geometry consistency, not visual
correctness or every VT semantics. The authorized-keys target uses only a
public test key already present in the product's fingerprint fixtures.

## Budgets

The checked-in corpora are limited to 32 files and 256 KiB per target. The
current corpora contain 15-19 seeds each. Input length limits are enforced by
the shared property before allocation; the corpus budget is separate.

The local qualification used libFuzzer's own budgets:

```sh
-timeout=2 -rss_limit_mb=512 -malloc_limit_mb=64 -seed=1 -print_final_stats=1
```

Mutation smoke limits were 10,000 executions or 20 seconds, except the channel
target (10,000 or 30 seconds) and the terminal target (5,000 or 20 seconds).
RSS sampling by libFuzzer is a diagnostic control, not a hard OS memory limit.

## Local qualification results

On the qualification host, all six targets built with AddressSanitizer and all
101 fixed seeds replayed successfully. A subsequent user-independent mutation
smoke run completed without a reported failure or retained failure artifact:

| Target | Executions | Peak RSS | Reported elapsed |
| --- | ---: | ---: | ---: |
| `channel_codec` | 10,000 | 120 MiB | 0 s (whole-second resolution) |
| `handshake_payload` | 10,000 | 38 MiB | 0 s |
| `wire_datagram` | 10,000 | 41 MiB | 0 s |
| `deframer` | 10,000 | 112 MiB | 0 s |
| `authorized_keys` | 10,000 | 60 MiB | 0 s |
| `terminal_feed_resize` | 5,000 | 290 MiB | 7 s |

The terminal result is the slowest because every iteration allocates a real
emulator. The combined cold ASAN build took about 2 minutes 15 seconds with a
reused Cargo cache; a warm build took 3.1 seconds. These are local observations,
not clean-machine costs or performance promises.

This is bounded mutation evidence for these targets. It does not prove full
input-space coverage, cryptographic correctness, live-connection behavior or
all terminal semantics. No product defect was found in these runs.

### Deliberate failure and reproducer control

The failure path was validated separately from product code: a temporary,
isolated copy of the channel target was patched to panic on a fixed marker,
built with AddressSanitizer, and run against a synthetic corpus. libFuzzer
wrote a 22-byte `crash-` artifact containing the marker. Minimization with a
raised diagnostic RSS limit (4,096 MiB for the minimizer only) could not reduce
the input further because the marker itself was the smallest trigger. The
minimized file still produced the same panic. The patched source was then
restored byte-for-byte (SHA-256
`694459e4e6c2ad0c9d18d8739d2b64b20d5be23e1ed705e401854749fce15249`) and no such
control exists in the repository. This validates failure retention,
reproduction and minimization; it is not a discovered product vulnerability.

The first minimization attempt used the normal 512 MiB diagnostic limit and
hit libFuzzer's allocation quarantine during its millions of internal steps.
The minimizer was rerun with a higher limit; the actual mutation runs retained
the normal limit.

## Reproducing locally

Prerequisites are the pinned `nightly-2026-10-24`, `cargo-fuzz 0.13.2`
installed from the verified official source and reviewed tool lock, and the
repository's pinned native OpenSSL prefix. See `DEPENDENCIES.md` for provenance
and security-check commands. Use owned directories:

```sh
export HOME="$OWNED/home"
export XDG_CONFIG_HOME="$OWNED/config"
export XDG_CACHE_HOME="$OWNED/cache"
export CARGO_HOME="$OWNED/cargo"
export RUSTUP_HOME="$OWNED/rustup"
export CARGO_TARGET_DIR="$OWNED/target"
export RUSTUP_TOOLCHAIN=nightly-2026-10-24
export HISTFILE=/dev/null
export CARGO_NET_OFFLINE=true

export X86_64_UNKNOWN_LINUX_GNU_OPENSSL_DIR="$OWNED/native-openssl"
export X86_64_UNKNOWN_LINUX_GNU_OPENSSL_STATIC=1
```

### Dependency source and lock preflight

The standalone workspace repeats the product's `vendor/vte` patch so terminal
fuzzing exercises the shipped parser, including its bounded OSC handling.
`tools/check_dependencies.py` compares every shared resolved package's version
and source identity (the canonical manifest path for local packages). Fuzz
versions must occur in the product graph; extra product packages or versions
are allowed. Equal version numbers alone do not establish source parity.

The intentional fuzz-only packages are `qsh-channel-fuzz`, `libfuzzer-sys`, and
its `arbitrary` and `jobserver` support dependencies. Features intentionally
differ: the isolated parser harness does not enable product runtime/platform
features, and its `ssh-key` edge names the public key type used by the harness.
The check therefore does not require whole-graph or feature-set equality.
Review feature changes separately when changing either manifest.

Before setting `CARGO_NET_OFFLINE=true`, fetch with both committed locks. Then
run the source check and record both hashes before building:

```sh
CARGO_NET_OFFLINE=false cargo fetch --locked --manifest-path Cargo.toml
CARGO_NET_OFFLINE=false cargo fetch --locked --manifest-path fuzz/Cargo.toml
python3 fuzz/tools/check_dependencies.py --offline
sha256sum Cargo.lock fuzz/Cargo.lock > "$OWNED/fuzz-locks.sha256"
CARGO_NET_OFFLINE=true cargo fuzz build --target x86_64-unknown-linux-gnu \
  --target-dir "$CARGO_TARGET_DIR"
sha256sum --check "$OWNED/fuzz-locks.sha256"
```

`cargo-fuzz 0.13.2` does not forward `--locked` to its build. Locked Cargo
metadata preflight, offline compilation, and the before/after lock hashes
prevent accepting a silently changed dependency graph. Commit intentional lock
updates explicitly and repeat the source check after dependency changes.

Generate the checked-in seeds and verify their inventory:

```sh
cargo run --manifest-path fuzz/Cargo.toml --example generate_corpus --locked --offline -- fuzz/corpus
for target in channel_codec handshake_payload wire_datagram deframer authorized_keys terminal_feed_resize; do
  python3 fuzz/tools/check_corpus.py "fuzz/corpus/$target/manifest.json" "fuzz/corpus/$target"
done
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s fuzz/tools -p 'test_*.py'
cargo test --manifest-path fuzz/Cargo.toml --locked --offline --lib
```

The generator updates seed files, not the manifests: review generated bytes and
update the manifest entries after an intentional recipe change.

Mutation adds files to its corpus directory, and each seed directory also holds
its `manifest.json`, which is not a seed. Run a target on a fresh owned copy,
never on `fuzz/corpus/<target>` itself. From the repository root:

```sh
cargo fuzz build channel_codec --target x86_64-unknown-linux-gnu --target-dir "$CARGO_TARGET_DIR"
run="$OWNED/fuzz-run/channel_codec"
mkdir -p "$run/corpus" "$run/artifacts"
find fuzz/corpus/channel_codec -maxdepth 1 -type f ! -name manifest.json \
  -exec cp {} "$run/corpus/" \;
cargo fuzz run channel_codec "$run/corpus" \
  --target x86_64-unknown-linux-gnu --target-dir "$CARGO_TARGET_DIR" -- \
  -artifact_prefix="$run/artifacts/" \
  -seed=1 -max_len=65537 -runs=10000 -max_total_time=30 \
  -timeout=2 -rss_limit_mb=512 -malloc_limit_mb=64 -print_final_stats=1
```

Use the corresponding `max_len` and seed directory for the other targets, and a
new `$run` directory for every run. A failing input is written to
`$run/artifacts/`; replay it with
`cargo fuzz run channel_codec "$run/artifacts/<file>" --target x86_64-unknown-linux-gnu --target-dir "$CARGO_TARGET_DIR"`.

The CI smoke check is `fuzz/tools/run_smoke.py`. It makes the same owned copies
under a work directory that must not exist yet, runs every listed target and
fails on a nonzero exit, a wall-clock timeout, a missing `#N DONE` completion
line (recognized within the first 256 bytes of a line), a
retained artifact or a sanitizer/panic marker anywhere in the output, printing
every reason with the last lines of the log. The complete output is classified
before the retained log is cut to its last 4 MiB. The runner reaps a target only
after signaling its whole process group, and escapes file names, paths and logged
bytes so they cannot act as GitHub workflow commands. To run it locally after
building all targets:

```sh
cargo fuzz build --target x86_64-unknown-linux-gnu --target-dir "$CARGO_TARGET_DIR"
python3 fuzz/tools/run_smoke.py \
  --binaries "$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release" \
  --seeds-root fuzz/corpus --work "$OWNED/fuzz-smoke" \
  channel_codec=65537 handshake_payload=512 wire_datagram=2048 \
  deframer=4096 authorized_keys=8192 terminal_feed_resize=8196
```

The inventory checker rejects missing or extra files, duplicate or invalid
names, non-regular files, size or SHA-256 mismatches, and exceeded count/byte
budgets. It only reads files; it does not execute a parser or a fuzz engine.

## CI strategy

`.github/workflows/fuzz.yml` is limited to pull requests and pushes that touch
`fuzz/`, the four local crates it uses (`transport`, `sshauth`, `terminal`,
and `terminal-size`), root dependency manifests/lock, vendored sources, native
crypto build inputs, or the workflow itself, plus manual dispatch. It installs
the pinned toolchain and verified `cargo-fuzz` source,
checks locked source parity, builds all six ASAN targets offline with unchanged
lock hashes, verifies every corpus manifest, runs the harness and tool tests,
and runs a short 1,000-execution smoke per target through
`fuzz/tools/run_smoke.py`. When the job fails, it uploads only the smoke run
logs (each at most 4 MiB) and libFuzzer's failing inputs as a workflow artifact
kept for 7 days. The inputs are mutations of the synthetic seeds; the mutated
corpora, toolchain and workspace are not uploaded. Continuous or scheduled fuzzing is not part
of CI; longer mutation runs remain a local qualification step because their
cost is not proportionate to every change.
