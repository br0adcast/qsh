#!/bin/bash
# Usage: in-process.sh OUT.jsonl PAIRS BUILD_DIRECTORY...
# Interleaved in-process harness runs of several builds, both modes, one
# process per workload; the build order rotates from pair to pair.
set -euo pipefail
out=$1; pairs=$2; shift 2
dirs=("$@")
workloads="idle stream-80x24 stream-200x50 stream-512x257 append-512x257 echo-200x50 alternate-200x50 alternate-512x257 combining-200x50 row-marks0-200x50 row-marks4-200x50 row-marks16-200x50 history-200x50 resize-200x50"
n=${#dirs[@]}
: > "$out"
for pair in $(seq 1 "$pairs"); do
  for k in $(seq 0 $((n - 1))); do
    dir=${dirs[$(( (k + pair - 1) % n ))]}
    b=$(basename "$dir")
    for w in $workloads; do
      for mode in alloc time; do
        flag=""; [ $mode = time ] && flag="--time"
        line=$("$dir/frame_storage" $flag $w)
        printf '{"pair":%d,"build":"%s","mode":"%s","result":%s}\n' "$pair" "$b" "$mode" "$line" >> "$out"
      done
    done
  done
done
