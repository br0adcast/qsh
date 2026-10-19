#!/usr/bin/env bash
# Run only on the selected target architecture, or with an explicit emulator.
set -euo pipefail
exec python3 "$(dirname "$0")/qualify_openssl.py" "$@"
