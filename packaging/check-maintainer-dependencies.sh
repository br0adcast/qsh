#!/usr/bin/env bash
# Read native dependency-query output on stdin; no package installation.
set -euo pipefail
[[ $# -eq 1 ]] || { echo 'usage: check-maintainer-dependencies.sh deb|rpm' >&2; exit 2; }
case $1 in
  deb)
    # A required alternative must not allow a different provider to omit useradd.
    awk 'BEGIN { RS=","; found=0 }
      { gsub(/^[[:space:]]+|[[:space:]]+$/, "") }
      /^passwd([[:space:]]*\([^)]*\))?$/ { found=1 }
      END {
        if (!found) print "missing direct Depends: passwd for qshd postinst" > "/dev/stderr"
        exit !found
      }'
    ;;
  rpm)
    # RPMSENSE_SCRIPT_POST = 1 << 10. Query decimal flags, not display labels
    # or capability names that merely contain a parenthesized word.
    awk -F '\t' 'BEGIN { needed["/usr/bin/getent"]=1; needed["/usr/sbin/useradd"]=1 }
      $1 in needed && $2 ~ /^[0-9]+$/ {
        if (int($2 / 1024) % 2 == 1) found[$1]=1
      }
      END {
        missing=0
        for (name in needed) if (!found[name]) {
          print "missing SCRIPT_POST dependency: " name > "/dev/stderr"
          missing=1
        }
        exit missing
      }'
    ;;
  *) echo 'unknown package dependency format' >&2; exit 2 ;;
esac
