#!/bin/sh
# Disposable test fixture only; never include this module in a release.
set -eu
if [ "$#" -ne 1 ]; then
    echo "usage: $0 OUTPUT_DIRECTORY" >&2
    exit 2
fi
mkdir -p "$1"
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
"${CC:-cc}" -shared -fPIC -Wall -Wextra -Werror \
    "$root/qshd/tests/fixtures/pam/session_groups.c" -lpam -o "$1/session_groups.so"
