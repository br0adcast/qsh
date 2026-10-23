#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
availability=$(bash "$script_dir/inspect-darwin-custody.sh")
printf '%s\n' "$availability"
if ! grep -Fxq 'availability=present_pending_mechanism_qualification' <<< "$availability"; then
  echo 'direct_child_mechanism=unsupported_preflight'
  exit 0
fi
qualification=$(mktemp -d "${TMPDIR:-/tmp}/qsh-darwin-direct-child.XXXXXXXX")
trap 'rm -rf -- "$qualification"' EXIT
sdk=$(xcrun --sdk macosx --show-sdk-path)
compiler=$(xcrun --sdk macosx --find clang)
# The static type assertion must compile BEFORE the program can fork.
"$compiler" -isysroot "$sdk" -Wall -Wextra -Werror \
  "$script_dir/darwin-direct-child.c" -o "$qualification/control"
mkdir "$qualification/home" "$qualification/cache" "$qualification/config"
HOME="$qualification/home" XDG_CACHE_HOME="$qualification/cache" \
  XDG_CONFIG_HOME="$qualification/config" HISTFILE=/dev/null \
  "$qualification/control"
