#!/usr/bin/env bash
# Availability evidence only: no process custody or signal delivery is tested.
set -euo pipefail
export LC_ALL=C

if [[ $(uname -s) != Darwin ]]; then
  echo 'Darwin custody inspection requires macOS' >&2
  exit 1
fi

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
sdk=$(xcrun --sdk macosx --show-sdk-path)
compiler=$(xcrun --sdk macosx --find clang)
printf 'macos_version=%s\n' "$(sw_vers -productVersion)"
printf 'macos_build=%s\n' "$(sw_vers -buildVersion)"
printf 'architecture=%s\n' "$(uname -m)"
printf 'sdk_version=%s\n' "$(xcrun --sdk macosx --show-sdk-version)"

inspection=$(mktemp -d "${TMPDIR:-/tmp}/qsh-darwin-custody.XXXXXXXX")
trap 'rm -rf -- "$inspection"' EXIT

# Distinguish a missing declaration from an unusable SDK/header.
printf '#include <libproc.h>\n' > "$inspection/header.c"
"$compiler" -isysroot "$sdk" -Wall -Wextra -Werror -fsyntax-only "$inspection/header.c"
cat > "$inspection/declaration.c" <<'EOF'
#include <libproc.h>
void qsh_inspect_declaration(void) { (void)&proc_signal_with_audittoken; }
EOF
declaration=present
if "$compiler" -isysroot "$sdk" -Wall -Wextra -Werror -fsyntax-only \
    "$inspection/declaration.c" > "$inspection/declaration.log" 2>&1; then
  cat "$inspection/declaration.log" >&2
else
  compile_status=$?
  cat "$inspection/declaration.log" >&2
  if [[ $compile_status == 1 ]] && \
      [[ $(grep -c ': error:' "$inspection/declaration.log") == 1 ]] && \
      grep -Fq "use of undeclared identifier 'proc_signal_with_audittoken'" \
        "$inspection/declaration.log"; then
    declaration=absent
  else
    echo 'Darwin declaration inspection failed; not an absence result' >&2
    exit "$compile_status"
  fi
fi
printf 'sdk_declaration=%s\n' "$declaration"

"$compiler" -isysroot "$sdk" -Wall -Wextra -Werror \
  "$script_dir/darwin-custody-availability.c" -o "$inspection/availability"
symbol=$("$inspection/availability")
case "$symbol" in
  present|absent|library_unavailable) ;;
  *) echo 'invalid Darwin symbol inspection result' >&2; exit 1 ;;
esac
printf 'runtime_symbol=%s\n' "$symbol"
echo 'custody_qualification=unqualified'
echo 'mechanism_tested=no'
if [[ $declaration != present || $symbol != present ]]; then
  echo 'availability=unsupported_for_further_qualification'
else
  echo 'availability=present_pending_mechanism_qualification'
fi
