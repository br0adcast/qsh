#!/usr/bin/env bash
# Checks how Linux-PAM reaches the qshd binary.
#
# qshd ships two ways. The featureless build is the statically linked musl
# portable release binary: Linux-PAM and libselinux must not reach it at all.
# The `system` build is the machine-wide daemon: it links
# libpam dynamically and must still start on Linux-PAM 1.3.1 (Ubuntu 20.04,
# RHEL 8), which has no LIBPAM_1.4 version node and so no
# pam_start_confdir -- a function only the tests may use.
#
# `ldd` cannot answer the first question: rustc links with --as-needed, so a
# `#[link(name = "pam")]` that leaked into the featureless build leaves no
# NEEDED entry behind while nothing calls PAM, and a leaked musl link quietly
# resolves `-lpam` to the host's static glibc libpam.a. The linker's own
# command line can answer it, so check 1 reads that.
#
#   1. featureless build, host gnu and host musl: no `-lpam` or `-lselinux`
#      on the link line; the musl binary has no NEEDED entry or system-library symbol.
#   2. `system` build, dev and release: libpam.so.0 is NEEDED, the only
#      libpam version required is LIBPAM_1.0, and pam_start_confdir is not
#      imported.
#   3. the loader: `qshd --version` from each `system` build starts against
#      qshd/tests/fixtures/libpam-1.3.1, a libpam without LIBPAM_1.4.
#
# Run it with no argument: checks 2 and 3 have something to look at. The
# per-login monitor (`qshd::helper::monitor`) calls `helper::pam` outside
# tests, so the `system` binary really does link libpam.
#
# `--featureless-only` is for the state this script was written in, and only
# that one: a tree where NO production code calls `helper::pam`. There the
# `system` binary needs no libpam (rustc links with --as-needed), check 2
# fails for want of a linkage to inspect, and check 3 never runs, so it
# cannot pass without the stand-in being loaded. The flag runs check 1 alone
# and exits 3, saying loudly that 2 and 3 did not run -- which is not a pass.
#
# Given a PATH instead, nothing is built and nothing in the tree is read:
# the script asks one question of that one already-built file.
#
#   4. the file imports no libpam symbol at a version node newer than
#      LIBPAM_1.0, requires no such node, and names pam_start_confdir
#      not at all -- so Linux-PAM 1.3.1 can resolve everything it asks
#      for.
#
# TWO SOURCES OF EVIDENCE, because neither covers the other. DT_VERNEED
# (`readelf -V`) lists the nodes the file needs from libpam.so.0 and is
# what the loader refuses the file over; it reads the same everywhere. The
# per-symbol nodes (`nm -D`) name which import is at fault, but only where
# nm prints them: binutils before 2.35 prints `pam_start` for an undefined
# symbol where 2.38 prints `pam_start@LIBPAM_1.0` -- Rocky 8 ships 2.30 --
# and a libpam built without a version script has no node to print either
# way. So the symbol names are read when they carry a node, DT_VERNEED is
# read always, and pam_start_confdir is caught by NAME, which is the one
# rule that holds however the two tools behave.
#
# That is the whole of what a binary of a FOREIGN architecture can be asked.
# `readelf -V` and `nm -D` read an aarch64 ELF on an x86_64 machine without
# difficulty, while check 1 needs a compiler and check 3 a loader for the
# file's own architecture. So this one check covers both architectures of a
# release from whichever machine built them, which is how
# `packaging/build-server-packages.sh` uses it: over each binary it is about
# to wrap in a package. Unlike --featureless-only this is not a partial run
# of the tree's checks but a whole answer to a narrower question, so a pass
# exits 0.
#
# A file that imports no pam_ symbol at all passes, and says so. That a
# binary reaches Linux-PAM at all is the NEEDED entry, which the packaging
# script checks per architecture; this check is about the version nodes.
#
# Usage: scripts/check-pam-linkage.sh [--featureless-only | <binary>]
#
# Environment: QSHD_PAM_LINKAGE_DIR -- where to build (default
# target/pam-linkage; one cargo target directory per build kind inside).
# Unused when a path is given: that path builds nothing.
#
# Exit status:
#   0  every check that was asked for ran and passed
#   1  a check failed, or something it needs is missing
#   2  bad usage
#   3  --featureless-only: check 1 passed; checks 2 and 3 were NOT run
set -euo pipefail

usage() {
  sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "$0" >&2
  exit 2
}

featureless_only=0
target_file=
case "${1-}" in
  "") ;;
  --featureless-only) featureless_only=1 ;;
  # Anything that is not a flag is the path of a built binary to inspect.
  # A mistyped flag must still be usage rather than a missing file, or
  # `--featureles-only` would be read as a filename and reported as such.
  -*) usage ;;
  *) target_file=$1 ;;
esac
[[ $# -le 1 ]] || usage

# Before the `cd` below, or a relative path would be read against the
# repository root and not against where the caller stood.
if [[ -n $target_file && $target_file != /* ]]; then
  target_file=$PWD/$target_file
fi

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
out=${QSHD_PAM_LINKAGE_DIR:-$root/target/pam-linkage}
fixture=$root/qshd/tests/fixtures/libpam-1.3.1
arch=$(uname -m)
gnu=$arch-unknown-linux-gnu
musl=$arch-unknown-linux-musl

failures=0

# A prerequisite is missing or a build broke: nothing after it means anything.
die() {
  echo "FAIL: $*" >&2
  exit 1
}
# A check did not hold: say so, and go on with the others.
fail() {
  echo "FAIL  $*" >&2
  failures=$((failures + 1))
}
ok() {
  echo "ok    $*"
}

# The libpam version nodes a binary requires, one per line.
libpam_versions() {
  readelf -V --wide "$1" | awk '
    /File:/ { file = ""; for (i = 1; i < NF; i++) if ($i == "File:") file = $(i + 1) }
    /Name:/ && file == "libpam.so.0" { for (i = 1; i < NF; i++) if ($i == "Name:") print $(i + 1) }'
}

# The pam_ functions among undefined symbols read on stdin, one
# `name@version` per line.
pam_filter() {
  awk '$NF ~ /^pam_/ { print $NF }' | sort -u
}

# The pam_ functions a binary imports, one `name@version` per line.
pam_imports() {
  nm -D --undefined-only "$1" | pam_filter
}

# --- check 4: one already-built file, of any architecture -------------------
# Reading a file needs neither cargo nor a compiler nor a loader, which is
# exactly what lets this be pointed at the aarch64 binary from an x86_64
# machine. The header says why this is the only one of the four checks that
# carries over to a foreign architecture, and why it exits 0 on its own.
if [[ -n $target_file ]]; then
  for tool in readelf nm; do
    command -v "$tool" >/dev/null || die "'$tool' is needed and was not found"
  done
  [[ -f $target_file ]] || die "not a file: $target_file"
  readelf -h "$target_file" >/dev/null 2>&1 || die "not an ELF file: $target_file"

  # THREE ANSWERS FROM nm, AND ONLY TWO OF THEM ARE ANSWERS. Measured:
  # a musl-static binary exits 0 and says "no symbols" on stderr -- it
  # has no dynamic symbol table, which is a real answer. A file nm cannot
  # read exits 1 saying "file format not recognized" -- that is not an
  # answer, and `readelf -h` accepts such a file, so the ELF guard above
  # does not catch it. Both used to arrive here as an empty list and pass
  # as "imports no pam_ symbol", which is a check reporting success for a
  # file it never read.
  nm_note=$(nm -D --undefined-only "$target_file" 2>&1 >/dev/null || true)
  if ! nm_out=$(nm -D --undefined-only "$target_file" 2>/dev/null); then
    die "nm could not read $target_file, so nothing about it was checked: ${nm_note:-nm failed without saying why}"
  fi
  dynamic_symbols=1
  case $nm_note in
    "") ;;
    *"no symbols"*) dynamic_symbols=0 ;;
    *) echo "note  nm said: $nm_note" >&2 ;;
  esac
  imports=$(pam_filter <<<"$nm_out")
  versions=$(libpam_versions "$target_file" 2>/dev/null | sort -u || true)
  # A bare name is not a symbol "newer than LIBPAM_1.0" and must not be
  # reported as one: see the header for the two ways a node goes missing
  # from this list (an nm older than 2.35, or a libpam built without a
  # version script). Where the node is missing, DT_VERNEED below is the
  # evidence.
  versioned=$(grep '@' <<<"$imports" | grep . || true)
  # Both halves of "newer than LIBPAM_1.0", because either can be empty on
  # its own: a symbol's version node is what the loader resolves the symbol
  # against, and the DT_VERNEED list is what it refuses the whole file for.
  newer_symbols=$(grep -v '@LIBPAM_1\.0$' <<<"$versioned" | grep . || true)
  newer_versions=$(grep -vx 'LIBPAM_1\.0' <<<"$versions" | grep . || true)
  # By name as well as by version node, which is what catches it on a
  # distribution that does not version its libpam: pam_start_confdir
  # arrived in Linux-PAM 1.4 whether or not anything labels it so, and
  # only the tests may name it.
  confdir=$(grep '^pam_start_confdir\(@\|$\)' <<<"$imports" | grep . || true)
  if [[ -n $confdir ]]; then
    fail "4: $target_file imports $(echo $confdir), which arrived in Linux-PAM 1.4 and only the tests may use"
  elif [[ -n $newer_symbols ]]; then
    fail "4: $target_file imports $(echo $newer_symbols): newer than LIBPAM_1.0, which Linux-PAM 1.3.1 cannot resolve"
  elif [[ -n $newer_versions ]]; then
    fail "4: $target_file requires libpam version node(s) $(echo $newer_versions); Linux-PAM 1.3.1 defines LIBPAM_1.0 alone"
  elif [[ $dynamic_symbols -eq 0 ]]; then
    ok "4: $target_file has no dynamic symbol table at all -- it is statically linked, so it imports nothing from libpam and there is nothing newer than LIBPAM_1.0 in it"
  elif [[ -z $imports ]]; then
    ok "4: $target_file imports $(grep -c . <<<"$nm_out") dynamic symbols and not one pam_ among them, so there is nothing newer than LIBPAM_1.0 in it (whether it needs libpam at all is not this check's question)"
  elif [[ -z $versioned ]]; then
    ok "4: $target_file: nm prints no version node on these imports, so the nodes are read from DT_VERNEED, which asks libpam.so.0 for ${versions:-no node at all}, and no import is named pam_start_confdir: $(echo $imports)"
  else
    ok "4: $target_file needs only LIBPAM_1.0 ($(echo $imports))"
  fi
  [[ $failures -eq 0 ]] || exit 1
  exit 0
fi

for tool in cargo rustup readelf nm cc; do
  command -v "$tool" >/dev/null || die "'$tool' is needed and was not found"
done
installed=$(rustup target list --installed)
grep -qx "$musl" <<<"$installed" || die "the $musl target is needed: rustup target add $musl"

# Build qshd's binary and print the linker command line it was linked with.
# A fresh binary is not linked again, and then rustc prints nothing -- which
# would read as "no -lpam". A build id unique to this run changes the link
# line, so the binary is always linked, and the output is checked to be a
# real link line before anything is read from it.
#   link_line <target-dir> <file for the link line> <cargo rustc args...>
link_line() {
  local dir=$1 file=$2
  shift 2
  local nonce
  nonce=$(printf '%08x%08x' "$(date +%s)" "$$")
  CARGO_TARGET_DIR=$dir cargo rustc -p qshd --bin qshd --locked "$@" -- \
    --print link-args -C "link-arg=-Wl,--build-id=0x$nonce" >"$file" ||
    die "building qshd failed: cargo rustc -p qshd --bin qshd $*"
  grep -q -- '/deps/qshd-' "$file" && grep -q -- "--build-id=0x$nonce" "$file" ||
    die "rustc printed no link line for qshd ($*); see $file"
}

# Whether a featureless link line passes a system-only library to the linker.
links_system_libs() {
  grep -Eq '(^|[[:space:]])"?-l(pam|selinux)"?([[:space:]]|$)' "$1"
}

mkdir -p "$out"

# --- check 1: the featureless build never links Linux-PAM -------------------
dir=$out/featureless-gnu
link_line "$dir" "$out/featureless-gnu.link" --target "$gnu"
if links_system_libs "$out/featureless-gnu.link"; then
  fail "1: the featureless $gnu build passes -lpam or -lselinux to the linker ($out/featureless-gnu.link)"
else
  ok "1: featureless $gnu: no -lpam or -lselinux on the link line"
fi

dir=$out/featureless-musl
link_line "$dir" "$out/featureless-musl.link" --target "$musl"
bin=$dir/$musl/debug/qshd
dynamic=$(readelf -d "$bin")
needed=$(grep -c '(NEEDED)' <<<"$dynamic" || true)
symbols=$(nm "$bin" | awk '$NF ~ /^(pam_|is_selinux_enabled$|getexeccon$|fgetfilecon$|fsetfilecon$|security_compute_relabel$|string_to_security_class$|freecon$)/ { n++ } END { print n + 0 }')
if links_system_libs "$out/featureless-musl.link"; then
  fail "1: the featureless $musl build passes -lpam or -lselinux to the linker ($out/featureless-musl.link)"
elif [[ $needed -ne 0 ]]; then
  fail "1: the featureless $musl binary has $needed NEEDED entries, expected none: $bin"
elif [[ $symbols -ne 0 ]]; then
  fail "1: the featureless $musl binary has $symbols PAM/libselinux symbols, expected none: $bin"
else
  ok "1: featureless $musl: no -lpam or -lselinux on the link line, no NEEDED entry, no PAM/libselinux symbol"
fi

if [[ $featureless_only -eq 1 ]]; then
  [[ $failures -eq 0 ]] || die "$failures check(s) failed"
  cat <<'EOF'

NOT RUN: checks 2 and 3 (the `system` build needs only LIBPAM_1.0 and
starts against Linux-PAM 1.3.1). --featureless-only was given, which asks
for check 1 alone. On this tree the monitor calls helper::pam, so those two
checks DO have something to look at -- run without the flag. This is NOT a
full pass (exit status 3).
EOF
  exit 3
fi

# --- the loader's stand-in for Linux-PAM 1.3.1 -------------------------------
stub=$out/libpam-1.3.1
mkdir -p "$stub"
cc -shared -fPIC -Wl,-soname,libpam.so.0 \
  -Wl,--version-script="$fixture/libpam.map" \
  -o "$stub/libpam.so.0" "$fixture/stub.c" ||
  die "building the libpam stand-in from $fixture failed"
stub_versions=$(readelf -V --wide "$stub/libpam.so.0" |
  awk '/Name: LIBPAM/ { for (i = 1; i < NF; i++) if ($i == "Name:") print $(i + 1) }' | sort -u)
[[ $stub_versions == LIBPAM_1.0 ]] ||
  die "the libpam stand-in must define LIBPAM_1.0 alone, it defines: $stub_versions"
stub_exports=$(nm -D --defined-only "$stub/libpam.so.0" | awk '$NF ~ /^pam_/ { print $NF }' | sort -u)

# --- checks 2 and 3, per profile ---------------------------------------------
dir=$out/system
for profile in dev release; do
  if [[ $profile == release ]]; then
    link_line "$dir" "$out/system-$profile.link" --features system --release
    bin=$dir/release/qshd
  else
    link_line "$dir" "$out/system-$profile.link" --features system
    bin=$dir/debug/qshd
  fi

  dynamic=$(readelf -d "$bin")
  if ! grep -q '(NEEDED).*\[libpam\.so\.0\]' <<<"$dynamic"; then
    fail "2 ($profile): qshd --features system does not need libpam.so.0, so nothing can say whether it loads on Linux-PAM 1.3.1 -- no production code calls helper::pam (until one does, run --featureless-only): $bin"
    fail "3 ($profile): not run: the binary does not load libpam at all: $bin"
    continue
  fi

  versions=$(libpam_versions "$bin" | sort -u)
  imports=$(pam_imports "$bin")
  if [[ $versions != LIBPAM_1.0 ]]; then
    fail "2 ($profile): qshd must require only LIBPAM_1.0 from libpam, it requires: $(echo $versions): $bin"
  elif grep -q '^pam_start_confdir@' <<<"$imports"; then
    fail "2 ($profile): qshd imports pam_start_confdir, which only the tests may use: $bin"
  else
    ok "2: system $profile: needs libpam.so.0, only LIBPAM_1.0, no pam_start_confdir ($(echo $imports))"
  fi

  # The stand-in must carry every LIBPAM_1.0 function qshd imports, or the
  # loader would refuse qshd for the stand-in's gap rather than for a real
  # incompatibility. Imports at any other version are the loader's to judge.
  wanted=$(sed -n 's/@LIBPAM_1\.0$//p' <<<"$imports" | sort -u)
  missing=$(comm -23 <(printf '%s\n' "$wanted") <(printf '%s\n' "$stub_exports" | sed 's/@.*//' | sort -u) | grep . || true)
  if [[ -n $missing ]]; then
    fail "3 ($profile): the libpam stand-in lacks $(echo $missing); add each to $fixture if Linux-PAM 1.3.1 exports it at LIBPAM_1.0"
    continue
  fi
  resolved=$(LD_LIBRARY_PATH=$stub ldd "$bin" 2>&1 || true)
  if ! grep -qF "libpam.so.0 => $stub/libpam.so.0 " <<<"$resolved"; then
    fail "3 ($profile): the loader would not pick the stand-in for libpam.so.0: $resolved"
  elif ! started=$(LD_LIBRARY_PATH=$stub "$bin" --version 2>&1); then
    fail "3 ($profile): qshd does not start against Linux-PAM 1.3.1: $started"
  else
    ok "3: system $profile: starts against the Linux-PAM 1.3.1 stand-in: $(head -n 1 <<<"$started")"
  fi
done

[[ $failures -eq 0 ]] || die "$failures check(s) failed"
echo
echo "All checks ran and passed."
