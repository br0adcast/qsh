#!/usr/bin/env bash
# Record the running build; a family prefix is never a capacity certificate.
set -euo pipefail
export LC_ALL=C
if [[ $(uname -s) != Darwin ]]; then
  echo 'Darwin primitive qualification requires macOS' >&2
  exit 1
fi
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
sdk=$(xcrun --sdk macosx --show-sdk-path)
compiler=$(xcrun --sdk macosx --find clang)
kernel_version=$(sysctl -n kern.version)
kernel_release=$(sysctl -n kern.osrelease)
kernel_build=$(sysctl -n kern.osversion)
architecture=$(uname -m)
sdk_version=$(xcrun --sdk macosx --show-sdk-version)
compiler_target=$("$compiler" -dumpmachine)
printf 'kern_version=%s\n' "$kernel_version"
printf 'kern_osrelease=%s\n' "$kernel_release"
printf 'kern_osversion=%s\n' "$kernel_build"
if uuid=$(sysctl -n kern.uuid 2>/dev/null); then
  printf 'kern_uuid=%s\n' "$uuid"
else
  echo 'kern_uuid=unavailable'
fi
printf 'native_architecture=%s\n' "$architecture"
printf 'selected_sdk_path=%s\n' "$sdk"
printf 'selected_sdk_version=%s\n' "$sdk_version"
printf 'compiler_target=%s\n' "$compiler_target"
echo 'capacity_source_mapping=unmapped'
echo 'capacity_qualification=unqualified'
qualification=$(mktemp -d "${TMPDIR:-/tmp}/qsh-darwin-primitives.XXXXXXXX")
trap 'rm -rf -- "$qualification"' EXIT
# Exact wrapper types and metadata layout must compile before actor creation.
"$compiler" -isysroot "$sdk" -Wall -Wextra -Werror \
  "$script_dir/darwin-native-primitives.c" -o "$qualification/control"
mkdir "$qualification/home" "$qualification/cache" "$qualification/config"
(
  cd "$qualification"
  HOME="$qualification/home" XDG_CACHE_HOME="$qualification/cache" \
    XDG_CONFIG_HOME="$qualification/config" HISTFILE=/dev/null \
    "$qualification/control"
)
