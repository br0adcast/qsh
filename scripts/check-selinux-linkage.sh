#!/usr/bin/env bash
# Check one already-built system ELF without loading it. Oldest supported
# libselinux imports are unversioned; a LIBSELINUX_1.0 requirement is also
# known, but a newer node has not been qualified on the old package floors.
set -euo pipefail
export LC_ALL=C

[[ $# -eq 1 && -f $1 ]] || { echo 'usage: check-selinux-linkage.sh <ELF file>' >&2; exit 2; }
for tool in readelf nm; do
  command -v "$tool" >/dev/null || { echo "FAIL: missing $tool" >&2; exit 1; }
done
bin=$1
readelf -h "$bin" >/dev/null || { echo "FAIL: unreadable ELF: $bin" >&2; exit 1; }
dynamic=$(readelf -d "$bin") || { echo "FAIL: readelf -d could not inspect $bin" >&2; exit 1; }
needed=$(sed -n 's/.*(NEEDED).*[\[]\([^]]*\)\].*/\1/p' <<<"$dynamic")
grep -Fxq 'libselinux.so.1' <<<"$needed" || {
  echo "FAIL: $bin has no DT_NEEDED libselinux.so.1" >&2; exit 1;
}
version_table=$(readelf -V --wide "$bin") || {
  echo "FAIL: readelf -V could not inspect $bin" >&2; exit 1;
}
versions=$(awk '
  /File:/ { file=""; for (i=1; i<NF; i++) if ($i=="File:") file=$(i+1) }
  /Name:/ && file=="libselinux.so.1" {
    for (i=1; i<NF; i++) if ($i=="Name:") print $(i+1)
  }' <<<"$version_table")
while IFS= read -r node; do
  [[ -z $node || $node == LIBSELINUX_1.0 ]] || {
    echo "FAIL: $bin requires unqualified libselinux node $node" >&2; exit 1;
  }
done <<<"$versions"
imports=$(nm -D --undefined-only "$bin") || {
  echo "FAIL: nm could not inspect $bin" >&2; exit 1;
}
while IFS= read -r symbol; do
  [[ -z $symbol || $symbol == *@LIBSELINUX_1.0 ]] || {
    echo "FAIL: $bin imports unqualified libselinux symbol $symbol" >&2; exit 1;
  }
done < <(awk '$NF ~ /@LIBSELINUX_/ { print $NF }' <<<"$imports")
echo "ok    $bin: DT_NEEDED libselinux.so.1; libselinux nodes ${versions:-unversioned}"
