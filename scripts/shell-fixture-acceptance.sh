#!/usr/bin/env bash
# Qualify compiled Linux fixtures in disposable Bash/Zsh passwd accounts.
# Usage: scripts/shell-fixture-acceptance.sh TARGET_DIR TEST_BINARY...
# Build with cargo test --no-run first and use the exact emitted executable paths.
set -euo pipefail
if [[ $(uname -s) != Linux ]]; then
  echo 'shell fixture acceptance requires Linux Docker and controlled system startup files' >&2
  exit 1
fi
if [[ $# -lt 2 ]]; then
  echo 'usage: shell-fixture-acceptance.sh TARGET_DIR TEST_BINARY...' >&2
  exit 2
fi
target=$(realpath "$1")
shift
for binary in "$target/debug/qsh" "$target/debug/qshd" "$@"; do
  [[ -x "$binary" && "$binary" == "$target/"* ]] || {
    echo 'expected executable inside the supplied Cargo target' >&2; exit 2;
  }
done
# Only this owned container is removed; no host accounts or shell configuration
# are changed. The target is mounted read-only; account-readable copies live in
# the container at their compiled-in paths.
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
name="qsh-shell-fixtures-$$"
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
# Dependency acquisition uses the distribution's authenticated apt metadata.
docker run -i --name "$name" --init --network bridge \
  --mount "type=bind,src=$target,dst=/fixtures,readonly" \
  --mount "type=bind,src=$script_dir/check-shell-fixture-output.py,dst=/check-shell-fixture-output.py,readonly" \
  ubuntu:24.04 bash -s -- "$target" "$@" <<'CONTAINER'
set -euo pipefail
target=$1
shift
timeout 180 bash -c 'apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends zsh openssh-server python3 binutils'
mkdir -p /run/sshd "$target/debug/deps"
for binary in "$target/debug/qsh" "$target/debug/qshd" "$@"; do
  cp "/fixtures/${binary#"$target/"}" "$binary"
  chmod 755 "$binary"
done
for shell in bash zsh; do
  account="qshfixture$shell"
  path=$(command -v "$shell")
  useradd -m -s "$path" "$account"
  passwd -d "$account" >/dev/null
  # The account shell is real passwd state. SHELL alone cannot qualify sshd's
  # interpreter selection. Every fixture still supplies a private session HOME.
  getent passwd "$account"
  for binary in "$@"; do
    count=$("$binary" --list | sed -n 's/^\([0-9][0-9]*\) tests\{0,1\}, 0 benchmarks$/\1/p')
    [[ ${count:-0} -gt 0 ]] || { echo 'no intended tests selected' >&2; exit 1; }
    echo "PASSWD_SHELL=$path BINARY=$(basename "$binary") EXPECTED_TESTS=$count"
    output=$(mktemp)
    set +e
    runuser -u "$account" -- env USER="$account" LOGNAME="$account" \
      SHELL="$path" HISTFILE=/dev/null QSH_REQUIRE_TEST_SHELLS=1 \
      QSH_TEST_QSHD="$target/debug/qshd" \
      timeout 420 "$binary" --test-threads=1 --nocapture 2>&1 | tee "$output"
    statuses=("${PIPESTATUS[@]}")
    set -e
    status=${statuses[0]}
    if [[ $status -eq 0 && ${statuses[1]} -ne 0 ]]; then status=${statuses[1]}; fi
    if ! python3 /check-shell-fixture-output.py "$count" "$status" "$output"; then
      # Keep a real binary/timeout failure's status; synthetic coverage failures
      # (all ignored, runtime skip, zero/partial execution) return one.
      if [[ $status -ne 0 ]]; then exit "$status"; fi
      exit 1
    fi
    rm -- "$output"
    # Surviving fixture processes would invalidate cleanup acceptance. The
    # container boundary ensures even a failure cannot leave host services.
    if ps -eo comm= | sed -n '/^\(qsh\|qshd\|sshd\)$/p' | read -r leftover; then
      echo 'fixture process survived test completion' >&2
      exit 1
    fi
  done
done
dpkg-query -W zsh zsh-common openssh-server python3
CONTAINER
