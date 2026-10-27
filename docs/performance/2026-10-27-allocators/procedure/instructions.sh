#!/bin/bash
# Usage: instructions.sh OUT.jsonl BUILD_DIRECTORY...
# User-space instructions per presented step in the in-process client
# harness, for each build directory: the workload's steps minus --steps 0.
set -euo pipefail
out=$1; shift
workloads="idle stream-80x24 stream-200x50 stream-512x257 append-512x257 echo-200x50 alternate-200x50 alternate-512x257 combining-200x50 row-marks0-200x50 row-marks4-200x50 row-marks16-200x50 history-200x50 resize-200x50"
ins() { sudo -n perf stat -x, -e instructions:u -- "$@" 2>&1 >/dev/null | awk -F, '/instructions/{print $1}'; }
: > "$out"
for dir in "$@"; do
  b=$(basename "$dir")
  for w in $workloads; do
    zero=$(ins "$dir/frame_storage" --time --steps 0 "$w")
    line=$("$dir/frame_storage" --time "$w")
    steps=$(echo "$line" | python3 -Ic 'import json,sys; print(json.load(sys.stdin)["steps"])')
    full=$(ins "$dir/frame_storage" --time "$w")
    printf '{"build":"%s","workload":"%s","steps":%s,"instructions_zero":%s,"instructions_full":%s}\n' "$b" "$w" "$steps" "$zero" "$full" >> "$out"
  done
done
