#!/usr/bin/env bash
# Check a generated package's actual runtime provider header on stdin.
set -euo pipefail
[[ $# -eq 1 ]] || { echo 'usage: check-runtime-dependencies.sh deb|rpm' >&2; exit 2; }
case $1 in
  deb)
    awk 'BEGIN { RS=","; found=0 }
      { gsub(/^[[:space:]]+|[[:space:]]+$/, "") }
      /^libselinux1([[:space:]]*\([^)]*\))?$/ { found=1 }
      END {
        if (!found) print "missing direct Depends: libselinux1" > "/dev/stderr"
        exit !found
      }'
    ;;
  rpm)
    awk 'BEGIN { found=0 }
      { gsub(/^[[:space:]]+|[[:space:]]+$/, "") }
      /^libselinux\.so\.1(\(\)|\(LIBSELINUX_1\.0\))?(\(64bit\))?$/ { found=1 }
      END {
        if (!found) print "missing exact Requires: libselinux.so.1 provider" > "/dev/stderr"
        exit !found
      }'
    ;;
  *) echo 'unknown package dependency format' >&2; exit 2 ;;
esac
