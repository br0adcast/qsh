#!/usr/bin/env bash
# Project entrypoint guard, not a downstream dependency build-script restriction.
set -euo pipefail
fail() { echo "unqualified Rust build: $*; see docs/terminal-resources.md" >&2; exit 1; }
for name in RUSTC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER CARGO_BUILD_RUSTC CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER; do
  [[ -z ${!name:-} ]] || fail "$name overrides the audited compiler path"
done
# Ask Cargo to invoke its selected compiler. Parsing Cargo configuration with
# grep misses valid dotted/quoted keys, inline tables and inherited settings.
# Keep the caller's working directory so Cargo resolves the same configuration
# and rustup toolchain as the following project build. A dependency-free probe
# uses its own target directory and never locks or changes the project's build.
probe=$(mktemp -d "${TMPDIR:-/tmp}/qsh-qualified-rust.XXXXXXXX")
trap 'rm -rf -- "$probe"' EXIT
cat > "$probe/Cargo.toml" <<'EOF'
[package]
name = "qsh-compiler-probe"
version = "0.0.0"
edition = "2021"
[lib]
path = "lib.rs"
[workspace]
EOF
: > "$probe/lib.rs"
version=$(cargo rustc --quiet --offline --manifest-path "$probe/Cargo.toml" \
  --target-dir "$probe/target" --lib -- -Vv) || fail "Cargo's compiler probe failed"
release=$(sed -n 's/^release: //p' <<<"$version")
hash=$(sed -n 's/^commit-hash: //p' <<<"$version")
case "$release/$hash" in
  1.98.1/48a229ceaefd4985c50990b14116b6d856af0985|1.99.1/58cf8f9c35b355199727627d07ae34a4e2846d67) ;;
  *) fail "compiler release/hash is outside the qualified allowlist" ;;
esac
printf '%s\n' "$version"
