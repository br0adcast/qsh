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
install_root=${CARGO_INSTALL_ROOT:-${CARGO_HOME:-$HOME/.cargo}}
mkdir -p -- "$install_root"
install_root=$(cd -- "$install_root" && pwd)
cargo install --root "$install_root" --path "$work/source/cargo-generate-rpm-0.21.0" --locked --force
python3 "$bundle/test_dependencies.py" "$install_root/bin/cargo-generate-rpm"
