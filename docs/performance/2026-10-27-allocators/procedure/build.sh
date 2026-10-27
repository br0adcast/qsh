#!/bin/bash
# Build qsh, qshd and the frame storage harness for one allocator variant.
#
# Run from the repository root at 2570c05 with ../allocator-evaluation.patch
# applied. OPENSSL_DIR must name the verified static prefix that
# scripts/build-openssl.sh prepared for TARGET; musl targets build with
# musl-gcc, as the release does. VARIANT is system, mimalloc, mimalloc-v2
# or jemalloc; the binaries are copied to OUT.
#
#   build.sh VARIANT TARGET OUT
set -euo pipefail
v=$1; target=$2; out=$3
features=()
harness=()
if [ "$v" != system ]; then
  features=(--features "qsh/alloc-$v,qshd/alloc-$v")
  harness=(--features "qsh/alloc-$v")
fi
case "$target" in
  *musl) export CC=musl-gcc "CC_${target//-/_}=musl-gcc" ;;
esac
export OPENSSL_STATIC=1 RUSTUP_TOOLCHAIN=1.99.1
cargo build --locked --release --target "$target" -p qsh -p qshd "${features[@]}"
cargo build --locked --release --target "$target" -p qsh --example frame_storage "${harness[@]}"
target_dir=${CARGO_TARGET_DIR:-target}
mkdir -p "$out"
cp "$target_dir/$target/release/qsh" "$target_dir/$target/release/qshd" \
  "$target_dir/$target/release/examples/frame_storage" "$out/"
