#!/usr/bin/env bash
# Shared by hosted client packaging and the floor server builder.
set -euo pipefail
bundle=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ ${1:-} == --prepare ]]; then
  shift
  exec python3 "$bundle/prepare.py" "$@"
fi
if [[ $# -ne 0 ]]; then
  echo 'usage: install.sh [--prepare NEW_DIRECTORY [--cache CRATE_DIRECTORY]]' >&2
  exit 2
fi
command -v cargo >/dev/null
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
python3 "$bundle/prepare.py" "$work/source"
cargo install --path "$work/source/cargo-generate-rpm-0.21.0" --locked --force
