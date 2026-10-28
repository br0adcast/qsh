#!/usr/bin/env bash
# Builds the `qshd` SERVER package -- the system-mode daemon -- for x86_64
# and aarch64, as a .deb and as an .rpm, in containers old enough that what
# comes out installs on the distributions people run. The finished packages
# land in dist/.
#
# This is the daemon that serves several accounts from one port, the way
# sshd does. It CANNOT be linked statically -- account lookup (NSS) and PAM
# both load modules at run time -- so it is built against glibc and libpam,
# and its glibc floor is whatever the machine that built it had. That is
# the whole reason for the containers: see packaging/Dockerfile.build-deb
# and packaging/Dockerfile.build-rpm, which say which release each floor
# comes from and why.
#
# The portable Linux daemon is built separately by the release workflow,
# statically linked against musl and without the `system` feature.
#
# THE TRAP THIS SCRIPT EXISTS TO AVOID. In both packaging tools the
# `target/release/` prefix in the asset list (cli/Cargo.toml) is magic: it
# is rewritten to follow `--target`. Build the server package without a
# glibc triple and the tool quietly picks up whatever musl binary is lying
# in target/release -- a package that looks right, installs, and has lost
# libpam entirely. Nothing in the build says a word. So every build below
# names a triple, and the check afterwards is made on the binary UNPACKED
# FROM THE FINISHED PACKAGE, not on the build tree: what shipped is the
# only thing worth inspecting.
#
# Usage: packaging/build-server-packages.sh [deb|rpm|all]
#
#   deb   Ubuntu 20.04 container:  qshd_<version>_amd64.deb, _arm64.deb
#   rpm   Rocky Linux 8 container: qshd-<version>.x86_64.rpm, .aarch64.rpm
#   all   both, which is also what no argument means
#
# Environment:
#   DOCKER  the container tool to drive (default: docker). Never run under
#           sudo: everything inside runs as the invoking user so that the
#           build tree and the packages are owned by that user.
#
# Exit status:
#   0  every package was built and passed its checks
#   1  a build or a check failed
#   2  bad usage
set -euo pipefail

usage() {
  sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "$0" >&2
  exit 2
}

root=$(cd "$(dirname "$0")/.." && pwd)
dist=$root/dist

die() {
  echo "FAIL: $*" >&2
  exit 1
}
say() {
  printf '\n== %s\n' "$*"
}
ok() {
  echo "ok    $*"
}

in_container=0
formats=()
while [[ $# -gt 0 ]]; do
  case $1 in
    --in-container) in_container=1 ;;
    deb | rpm) formats+=("$1") ;;
    all) formats=(deb rpm) ;;
    -h | --help) usage ;;
    *) usage ;;
  esac
  shift
done
[[ ${#formats[@]} -gt 0 ]] || formats=(deb rpm)

# Each architecture, with everything that differs about it: the Rust
# target, what dpkg and rpm call the architecture, the strip that
# understands the file, and the word `file` prints for the machine.
targets=(
  "x86_64-unknown-linux-gnu  amd64 x86_64  strip                    x86-64"
  "aarch64-unknown-linux-gnu arm64 aarch64 aarch64-linux-gnu-strip  ARM aarch64"
)

# ---------------------------------------------------------------------------
# On the host: build each image and run this same script inside it.
# ---------------------------------------------------------------------------
if [[ $in_container -eq 0 ]]; then
  docker=${DOCKER:-docker}
  command -v "$docker" >/dev/null || die "'$docker' was not found; set DOCKER= to the container tool to use"
  [[ $(id -u) -ne 0 ]] || echo "warning: running as root -- the build tree and packages will be owned by root" >&2

  mkdir -p "$dist"
  for fmt in "${formats[@]}"; do
    image=qshd-build-$fmt:local
    say "$fmt: building the build image $image"
    "$docker" build -f "$root/packaging/Dockerfile.build-$fmt" -t "$image" "$root/packaging"

    # A target directory of its own per format, for two reasons: a build
    # here must not invalidate the developer's own target/ (a different
    # rustc, a different glibc -- everything would be rebuilt, twice, every
    # time), and the two containers must not invalidate each other's.
    # CARGO_HOME goes beside it so the registry survives between runs;
    # HOME, because a container user has none.
    work=/work/target/package/$fmt
    mkdir -p "$root/target/package/$fmt"/{home,cargo,target}

    # Nothing of this format survives into the run. A package left from an
    # earlier build is a package that can be picked up, checked and
    # reported as this run's work -- and it would be checked against
    # today's promises while carrying yesterday's contents.
    case $fmt in
      deb) rm -f "$dist"/qshd_*.deb ;;
      rpm) rm -f "$dist"/qshd-*.rpm ;;
    esac

    say "$fmt: building the packages inside $image"
    # --user: everything this leaves on the bind mount -- the build tree,
    # the packages -- is owned by the invoking user, not by root. Without
    # it the developer would be left with a target/ they cannot delete.
    "$docker" run --rm \
      --user "$(id -u):$(id -g)" \
      --volume "$root:/work" \
      --workdir /work \
      --env HOME="$work/home" \
      --env CARGO_HOME="$work/cargo" \
      --env CARGO_TARGET_DIR="$work/target" \
      "$image" packaging/build-server-packages.sh --in-container "$fmt"
  done

  say "done"
  ls -l "$dist"
  exit 0
fi

# ---------------------------------------------------------------------------
# Inside the container: one format, both architectures.
# ---------------------------------------------------------------------------
[[ ${#formats[@]} -eq 1 ]] || die "--in-container takes exactly one format"
fmt=${formats[0]}
cd "$root"
export RUSTUP_TOOLCHAIN=1.98.1
"$root/scripts/check-qualified-rust.sh"
target_dir=${CARGO_TARGET_DIR:-$root/target}
mkdir -p "$dist"

# The glibc floor this image promises, declared by the image itself
# (packaging/Dockerfile.build-$fmt) and nowhere else, so that the promise
# and the machine that keeps it cannot drift apart. The image checks the
# declaration against its own libc at build time; this script checks every
# package it makes against the declaration.
floor=${QSHD_GLIBC_FLOOR:-}
[[ -n $floor ]] || die "QSHD_GLIBC_FLOOR is not set: the build image must declare the glibc floor it promises (packaging/Dockerfile.build-$fmt sets it)"

# Every tool this run will reach for, named before any of them is reached
# for. A missing one otherwise surfaces in the middle of the packaging
# step, minutes into a build, as a shell error about a word rather than as
# "the image is missing cpio" -- and the format-specific half is exactly
# where an image and this script drift apart.
tools=(cargo python3 readelf nm file find sort "$root/scripts/check-pam-linkage.sh" "$root/scripts/check-selinux-linkage.sh" "$root/packaging/check-runtime-dependencies.sh")
case $fmt in
  deb) tools+=(cargo-deb dpkg-deb dpkg-shlibdeps) ;;
  rpm) tools+=(cargo-generate-rpm rpm rpm2cpio cpio) ;;
esac
for tool in "${tools[@]}"; do
  command -v "$tool" >/dev/null ||
    die "'$tool' is needed inside the $fmt container and was not found -- packaging/Dockerfile.build-$fmt should install it"
done

# Local invocations also require one consistent shipped pair. CI checks the
# tag before launching these containers; here the same checkout supplies the
# selected version, independent of a developer's branch name.
version=$(cargo metadata --locked --format-version 1 --no-deps \
  | python3 "$root/scripts/check-release-version.py" --ref-type branch --ref-name local)

# What a shipped system-mode binary must be, wherever it came from. Every
# one of these has a way of being quietly false: `--features system`
# forgotten leaves a binary with no PAM at all; the magic `target/release/`
# prefix leaves the musl binary, which is statically linked and also has no
# PAM; a cross build gone wrong leaves the host's architecture in a package
# labelled for the other one.
check_binary() {
  local bin=$1 machine=$2 what=$3 description needed
  [[ -f $bin ]] || die "$what: no such file: $bin"
  description=$(file -b "$bin")
  case $description in
    *"dynamically linked"*) ;;
    *) die "$what is not dynamically linked, so it could load neither an NSS nor a PAM module: $description" ;;
  esac
  case $description in
    *"$machine"*) ;;
    *) die "$what is not $machine: $description" ;;
  esac
  needed=$(readelf -d "$bin" | sed -n 's/.*(NEEDED).*\[\(.*\)\].*/\1/p' | tr '\n' ' ')
  case $needed in
    *libpam.so.0*) ;;
    *) die "$what does not need libpam.so.0 -- built without the 'system' feature, or built from the wrong target directory (NEEDED: $needed)" ;;
  esac
  "$root/scripts/check-selinux-linkage.sh" "$bin"
  ok "$what: $description"
  ok "$what: NEEDED $needed"
}

# The highest glibc a finished package admits to needing, against the
# highest this image is allowed to produce.
#
# THIS IS THE PROPERTY THE CONTAINERS EXIST FOR, and it is the one with no
# local symptom: a package built against too new a libc compiles, links,
# installs on the machine that built it and passes every other check here.
# It fails on a user's older machine, months later, as `apt install`
# refusing a dependency. It has already gone wrong once on this branch --
# a deb whose floor was two releases too high -- and nothing said a word.
# The highest glibc version node the file ITSELF asks for, read from
# DT_VERNEED: what the loader will go looking for, rather than what some
# tool computed about the file.
#
# THIS IS THE AUTHORITY, AND dpkg-shlibdeps IS NOT. Run inside this image
# over a binary that genuinely needs GLIBC_2.34 -- a build tree left
# behind by an older image with a newer libc, which cargo cannot tell
# from a fresh one because the rustc fingerprint is identical --
# dpkg-shlibdeps warns about each symbol it cannot resolve, emits
# `libc6 (>= 2.30)` anyway, and exits 0. Such a package passes every
# check, installs on the oldest system promised, and dies at exec. The
# rpm side never had this hole: rpm's find-requires reads the ELF.
#
# `|| true` so that a file with NO glibc node answers "nothing" instead of
# killing the script: under `set -o pipefail` the empty `grep` fails the
# pipeline, the command substitution fails with it, and the build stops
# with no word about why. A binary with its .gnu.version_r removed is
# exactly that file -- and dpkg-shlibdeps answers `libc6 (>= 2.2.5)` for
# it, so it must be refused with a sentence, not a silence.
binary_glibc_floor() {
  readelf -V --wide "$1" | grep -oE 'GLIBC_[0-9.]+' | sed 's/^GLIBC_//' | sort -V | tail -n 1 || true
}

# `sort -V` throughout, never plain `sort`, and this is load-bearing
# rather than tidy: glibc version nodes are dotted numbers, not strings.
# The x86_64 binary really does carry a GLIBC_2.9 node, which plain sort
# ranks ABOVE 2.28 -- so a byte comparison would report a floor of 2.9,
# call it higher than the promise, and fail every build for a reason that
# does not exist. Do not let an edit turn these back into `sort`.
check_floor() {
  local what=$1 found=$2 highest
  [[ -n $found ]] ||
    die "$what names no glibc requirement at all, so its floor cannot be checked -- the dependency data is not what this expects"
  highest=$(printf '%s\n%s\n' "$found" "$floor" | sort -V | tail -n 1)
  [[ $highest == "$floor" ]] ||
    die "$what records a glibc floor of $found, above the $floor this image promises: it was built against a newer libc than intended -- a changed base image, or a build tree left behind by one"
  ok "$what: glibc floor $found, within the $floor this image promises"
}

for row in "${targets[@]}"; do
  read -r triple deb_arch rpm_arch strip_tool machine <<<"$row"

  native_args=()
  if [[ $triple == aarch64-unknown-linux-gnu ]]; then
    native_args+=(--cc aarch64-linux-gnu-gcc --ar aarch64-linux-gnu-ar --ranlib aarch64-linux-gnu-ranlib)
  fi
  native_prefix=$(bash "$root/scripts/build-openssl.sh" --target "$triple" \
    --cache "$target_dir/native-crypto" --toolchain-id "package-floor-$fmt" \
    --jobs 2 "${native_args[@]}")
  export OPENSSL_DIR="$native_prefix" OPENSSL_STATIC=1
  say "$fmt/$triple: building qshd with --features system"
  cargo build --release --locked -p qshd --features system --target "$triple"
  bin=$target_dir/$triple/release/qshd

  # The cross strip, not the host's: `strip` understands one architecture.
  command -v "$strip_tool" >/dev/null || die "'$strip_tool' is needed and was not found"
  "$strip_tool" "$bin"

  check_binary "$bin" "$machine" "$fmt/$triple: the built binary"
  # The version nodes, which is the one thing a foreign-architecture ELF
  # can be asked about from here. Linux-PAM 1.3.1 (RHEL 8, Ubuntu 20.04)
  # has no LIBPAM_1.4, so a symbol from it would not resolve there.
  "$root/scripts/check-pam-linkage.sh" "$bin"

  say "$fmt/$triple: making the package"
  tmp=$(mktemp -d)
  # shellcheck disable=SC2064 # $tmp is meant to expand now, not at exit
  trap "rm -rf '$tmp'" EXIT
  # Everything below is checked against the package this run made. The
  # way that is made true is deletion, not timestamps: nothing of this
  # architecture's shape exists when the packaging tool runs, so anything
  # of that shape afterwards was written by it. Comparing mtimes against
  # a mark -- what this did before -- rests on granularity the shell does
  # not promise: `-nt` compares whole seconds in some shells and on some
  # filesystems, container and host need not agree about the clock, and a
  # package written within the same second as the mark reads as "not
  # newer". Absence has no granularity.
  payload=$tmp/payload
  mkdir -p "$payload"
  case $fmt in
    deb)
      # --no-build because the binary above is the one to ship; --no-strip
      # because it has already been stripped, by a strip that understands
      # it. `$auto` in the qshd variant makes cargo-deb ask
      # dpkg-shlibdeps, which reads the foreign architecture's shared
      # libraries out of the container's multiarch tree.
      rm -f "$dist"/qshd_*_"$deb_arch".deb
      out=$(cargo deb -p qsh --variant qshd --no-build --no-strip --target "$triple" -o "$dist/")
      pkg=$(tail -n 1 <<<"$out")
      [[ -f $pkg ]] || pkg=$(find "$dist" -maxdepth 1 -name "qshd_*_$deb_arch.deb" | head -n 1)
      [[ -n $pkg && -f $pkg ]] || die "cargo deb produced no package for $triple: $out"

      python3 "$root/scripts/check-release-output.py" package --format deb --program qshd \
        --version "$version" --arch "$deb_arch" "$pkg"
      declared=$(dpkg-deb -f "$pkg" Architecture)
      [[ $declared == "$deb_arch" ]] || die "$pkg says Architecture: $declared, expected $deb_arch"
      ok "$(basename "$pkg"): Architecture: $declared"
      depends=$(dpkg-deb -f "$pkg" Depends)
      ok "$(basename "$pkg"): Depends: $depends"
      # The dependency line, not just the ELF: a package whose binary needs
      # libpam but whose control file does not say so installs onto a
      # machine without libpam and fails at the first login instead of at
      # `apt install`. Empty is the shape this takes when dpkg-shlibdeps
      # could not read the foreign architecture's libraries.
      case $depends in
        *libpam0g*) ;;
        *) die "$pkg depends on '$depends', which does not name libpam0g" ;;
      esac
      "$root/packaging/check-runtime-dependencies.sh" deb <<<"$depends"
      # Every libc6 clause there is, highest wins. This was one greedy
      # `sed 's/.*libc6 (>= \(...\)).*/'`, which takes the LAST match
      # rather than the largest: with one clause on the line the two
      # coincide, and on the day there are two the check would quietly
      # read the wrong number.
      #
      # `|| true` because this is an ASSIGNMENT, and an assignment from a
      # pipeline takes that pipeline's status: `grep` exits 1 when the
      # Depends line carries no libc6 clause at all, and under `set -e`
      # the run would end there, mute, before check_floor could say
      # "names no glibc requirement at all" -- the sentence written for
      # precisely that case. The same extraction as an ARGUMENT (the rpm
      # side below) is safe without it: the empty value reaches the guard
      # and the guard speaks. `sed -n`, which this replaced, exits 0 on no
      # match and hid the difference.
      declared=$(grep -oE 'libc6 \(>= [0-9.]+\)' <<<"$depends" | sed -E 's/.*>= ([0-9.]+)\)/\1/' | sort -V | tail -n 1 || true)
      check_floor "$(basename "$pkg"): the Depends line" "$declared"
      # And the line must not promise LESS than the binary needs, which is
      # the other half of the same defect: apt installs the package where
      # the loader cannot start it. The authority is the ELF, checked for
      # both formats after the package is opened; this is what catches the
      # dependency line disagreeing with it.
      needs=$(binary_glibc_floor "$bin")
      [[ -n $needs ]] || die "$(basename "$pkg"): the binary asks for no glibc version node at all, which is not something this build can produce"
      [[ $(printf '%s\n%s\n' "$declared" "$needs" | sort -V | head -n 1) == "$needs" ]] ||
        die "$(basename "$pkg") says libc6 (>= $declared) while its binary asks the loader for GLIBC_$needs: dpkg-shlibdeps under-declared the dependency, and apt would install this where it cannot run"
      ok "$(basename "$pkg"): Depends libc6 (>= $declared), binary asks for GLIBC_$needs"
      dpkg-deb -x "$pkg" "$payload"
      ;;
    rpm)
      # --auto-req is given explicitly and never left to its default.
      # `auto` means "/usr/lib/rpm/find-requires if it is there, an
      # ldd-based imitation otherwise", so with it the Requires: line of a
      # release would depend on whether rpm happened to be installed on
      # the build machine. The container installs rpm-build for this.
      rm -f "$dist"/qshd-*."$rpm_arch".rpm
      out=$(cargo generate-rpm -p cli --variant qshd --target "$triple" --auto-req find-requires -o "$dist/")
      pkg=$(tail -n 1 <<<"$out")
      [[ -f $pkg ]] || pkg=$(find "$dist" -maxdepth 1 -name "qshd-*.$rpm_arch.rpm" | head -n 1)
      [[ -n $pkg && -f $pkg ]] || die "cargo generate-rpm produced no package for $triple: $out"

      python3 "$root/scripts/check-release-output.py" package --format rpm --program qshd \
        --version "$version" --arch "$rpm_arch" "$pkg"
      declared=$(rpm -qp --qf '%{ARCH}' "$pkg" 2>/dev/null)
      [[ $declared == "$rpm_arch" ]] || die "$pkg says arch $declared, expected $rpm_arch"
      ok "$(basename "$pkg"): arch $declared"
      requires=$(rpm -qp --requires "$pkg" 2>/dev/null)
      sed 's/^/ok    Requires: /' <<<"$requires"
      # The same reason as the deb side: the control data has to name the
      # library too, or the package installs where it cannot run.
      case $requires in
        *libpam.so.0*) ;;
        *) die "$pkg requires no libpam.so.0: $(tr '\n' ' ' <<<"$requires")" ;;
      esac
      "$root/packaging/check-runtime-dependencies.sh" rpm <<<"$requires"
      # rpm records one requirement per version node per library, so the
      # floor is the highest GLIBC_ node over all of them -- libc.so.6 is
      # not the only library that carries them.
      check_floor "$(basename "$pkg")" \
        "$(grep -oE 'GLIBC_[0-9.]+' <<<"$requires" | sed 's/^GLIBC_//' | sort -V | tail -n 1)"
      rpm2cpio "$pkg" | (cd "$payload" && cpio -idm --quiet)
      ;;
  esac

  # The binary as the package carries it. Everything above could pass and
  # this still fail: it is the only step that inspects what a user would
  # actually install.
  check_binary "$payload/usr/bin/qshd" "$machine" "$(basename "$pkg"): /usr/bin/qshd"
  "$root/scripts/check-pam-linkage.sh" "$payload/usr/bin/qshd"
  # The floor of the file that will be installed, taken from the file.
  # Both formats, one way: rpm's Requires are derived from this same ELF
  # by find-requires, and the deb's Depends are not derived from it at
  # all -- see binary_glibc_floor for what that costs.
  check_floor "$(basename "$pkg"): /usr/bin/qshd" "$(binary_glibc_floor "$payload/usr/bin/qshd")"
  rm -rf "$tmp"
  trap - EXIT
done

say "$fmt: every package built and every check passed"
