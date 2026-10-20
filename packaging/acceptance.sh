#!/usr/bin/env bash
# Acceptance tier for the `qshd` SERVER package (task 9b of the
# system-mode-slice3 plan): proves design §11's layer 3 over the package
# that actually ships, not over the build tree.
#
# WHY THE INSTALLED PACKAGE, AND NOT THE BUILD TREE. Everything below runs
# against a fresh container with the real `.deb`/`.rpm` INSTALLED by the
# family's own tool (`dpkg -i`/`dnf install`) -- never against a binary
# copied in from `target/`. That is not ceremony: earlier in this same
# slice, a change to where the daemon writes its log broke this whole tier
# outright (five suites, zero passing), and three rounds of review missed
# it -- because review reads code, and nobody had run the real thing. This
# script is what runs the real thing.
#
# THE SECURITY PROPERTY THIS EXISTS TO PROVE (design §11, the main
# regression test for the whole slice): two real accounts, two real keys,
# each gets a shell running as ITSELF -- and an account presenting another
# account's live session token gets its own refusal, never that account's
# session. See `security_regression` below.
#
# WHY A HAND-ROLLED WIRE CLIENT (`qshd/examples/acceptance_client.rs`)
# INSTEAD OF `qsh` ITSELF. `qsh` is interactive-only: raw terminal mode, an
# on-first-contact trust prompt, no batch/one-shot mode -- nothing here to
# script non-interactively. The only other thing in this workspace that
# already speaks the real wire protocol (Noise handshake, SSH-signature
# proof, channel framing) is the root-gated test harness in
# `qshd/tests/common/mod.rs`, and it cannot be reused as-is: it spawns the
# daemon via `CARGO_BIN_EXE_qshd`, a build-tree path baked in by Cargo at
# COMPILE TIME, which is exactly the thing this tier must not depend on.
# `acceptance_client` is the same shape of client, built from the same
# crates, but driven by CLI arguments and run against whatever `--port` and
# `--server-pub` this script hands it -- the installed daemon's, inside the
# container. See that file's own header for the rest of the argument. It
# never ships: an example target is not part of the release build, and this
# script builds and runs it ONLY on the host that is driving the
# containers -- see the network design below.
#
# NETWORK DESIGN: everything in one container, on Docker's ordinary bridge
# network -- no `--network host`. The daemon binds 0.0.0.0:<port> inside
# the container; `acceptance_client` (built statically against musl, so it
# runs unmodified regardless of the container's glibc) is copied in and run
# there too, over the container's own loopback, driven entirely through
# `docker exec`. Not a host-side client reaching into the container by IP:
# a sandboxed CI runner's own network namespace is not guaranteed to reach
# a container's published ports or its bridge IP by a raw connect (measured
# while writing this script -- see the task report), while `docker exec`
# always works, because it goes through the Docker API rather than through
# IP routing. Running both sides inside the container is not a workaround
# for that reason alone; it is also the more faithful shape of what is
# being proven (nothing about "two accounts on one box" needs the client
# and the server to be on different hosts), and it means this script never
# has to pick a host port that might collide with something else running
# on the same CI runner.
#
# WHAT IS NOT DONE, ON PURPOSE: systemd is never started as PID 1. Neither
# `ubuntu:20.04` nor `rockylinux:8` gives that without real work, and the
# work would prove systemd, not the daemon. The unit files are checked as
# FILES -- present, and syntactically sound where `systemd-analyze` exists
# to ask -- and the installed binary is started directly, as root, the way
# `packaging/qshd-system.service`'s own `ExecStart` would. The cost: this
# script does not prove `systemctl enable --now qshd` works. That is a
# real gap, left to a live-machine acceptance the way the plan's own
# amendment says to leave it.
#
# Usage:
#   packaging/acceptance.sh <path-to-qshd-package.deb-or-.rpm>
#
# The package's own file name decides everything else: its extension picks
# the family (dpkg/apt for `.deb`, dnf for `.rpm`), and its architecture
# suffix (amd64/x86_64 vs arm64/aarch64 -- `packaging/build-server-packages.sh`
# names every package it makes exactly this way) picks the tier:
#
#   x86_64/amd64  the FULL tier: install, accounts, PAM, the unit file,
#                 two real logins each running as themselves, the §10 log
#                 line contract (all three shapes), the daemon's refusal to
#                 start without its PAM service file, and the security
#                 regression test.
#   aarch64/arm64 the CHEAP tier (design §11's own words: "two properties,
#                 both cheap"): the package installs, and the daemon
#                 refuses to start without its PAM service file. Nothing
#                 else -- an emulated login costs real minutes for no
#                 additional knowledge (x86_64 and aarch64 do not diverge
#                 in anything this tier checks; only the two PAM families
#                 do, and that is already covered once per family on
#                 x86_64). The cheap tier still needs the REAL binary to
#                 execute, under qemu-user emulation
#                 (`docker/setup-qemu-action` in CI; `docker run --rm
#                 --privileged tonistiigi/binfmt --install arm64` locally),
#                 which is exactly the gap this exists to close: an
#                 aarch64 asset has shipped from this project once before
#                 without ever having been installed on the architecture it
#                 targets.
#
# Environment:
#   DOCKER  the container tool to drive (default: docker).
#
# The FULL tier additionally needs a Rust toolchain with the
# x86_64-unknown-linux-musl target on THIS machine (not in any container):
# it builds `acceptance_client` once, on the host, the same way any other
# `cargo build` step in this workspace would. The CHEAP tier needs neither
# cargo nor that binary.
#
# Exit status:
#   0  every check for this package's tier passed
#   1  a check failed
#   2  bad usage
set -euo pipefail

usage() {
  sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "$0" >&2
  exit 2
}

root=$(cd "$(dirname "$0")/.." && pwd)

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

[[ $# -eq 1 ]] || usage
pkg=$1
[[ -f $pkg ]] || die "no such package: $pkg"
docker=${DOCKER:-docker}
command -v "$docker" >/dev/null || die "'$docker' was not found; set DOCKER= to the container tool to use"
command -v cmp >/dev/null || die "'cmp' (diffutils) is required on the host for byte-exact profile checks"

base=$(basename -- "$pkg")
case $base in
  *.deb) fmt=deb ;;
  *.rpm) fmt=rpm ;;
  *) die "$base: not a .deb or .rpm -- this script only knows those two families" ;;
esac
case $base in
  *amd64* | *x86_64*) arch=x86_64 ;;
  *arm64* | *aarch64*) arch=aarch64 ;;
  *) die "$base: its name names neither amd64/x86_64 nor arm64/aarch64 -- can't pick a tier" ;;
esac

# The exact floor image each family's build container declares, read from
# THAT Dockerfile rather than repeated here: a floor written in two places
# is a floor that can disagree with itself (packaging/build-server-packages.sh
# makes the same choice, for the same reason, about QSHD_GLIBC_FLOOR). This
# is also what keeps the two amendments this task carries true by
# construction rather than by discipline: whichever image the build
# actually used for that family is the one this script installs the
# package into, pinned by the SAME digest, so "the floor, not a fresh
# system" cannot drift between build and acceptance.
floor_image() {
  local dockerfile="$root/packaging/Dockerfile.build-$1"
  [[ -f $dockerfile ]] || die "no such Dockerfile: $dockerfile"
  local image
  image=$(sed -n 's/^FROM \(.*\)$/\1/p' "$dockerfile" | head -n 1)
  [[ -n $image ]] || die "$dockerfile has no FROM line"
  printf '%s' "$image"
}
image=$(floor_image "$fmt")

container="qshd-acceptance-$fmt-$arch-$$"
native_uapi=
pam_snapshot=
cleanup() {
  [[ -z $pam_snapshot ]] || rm -f "$pam_snapshot"
  [[ -z $native_uapi ]] || rm -rf "$native_uapi"
  "$docker" rm -f "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT

say "$fmt/$arch: $base against $image"

# ---------------------------------------------------------------------------
# Install, on the platform the package's own name claims -- pinned, and
# then checked for real, on BOTH architectures.
# ---------------------------------------------------------------------------
expected_machine=x86_64
expected_platform=linux/amd64
if [[ $arch == aarch64 ]]; then
  expected_machine=aarch64
  expected_platform=linux/arm64
fi
platform_flag=(--platform "$expected_platform")

# Two different failures land on this same `docker run`, and they need two
# different messages: qemu-user really can be unregistered (the original
# diagnosis below), but a MUCH more likely cause locally is Docker's own
# image cache refusing a platform it does not already have under this exact
# tag+digest -- "cannot overwrite digest" -- which happens whenever this
# script's other architecture ran against the same Dockerfile first in the
# same Docker install (measured while writing this fix: run the x86_64 deb
# tier, then this one, against unmodified `dist/`, and it reproduces every
# time). Telling that reader to reinstall qemu, which was never the
# problem, sends them chasing a fix that does nothing -- so stderr is
# captured and inspected instead of guessed at.
docker_run_err=$("$docker" run -d --name "$container" "${platform_flag[@]}" "$image" sleep infinity 2>&1 >/dev/null) &&
  docker_run_status=0 || docker_run_status=$?
if [[ $docker_run_status -ne 0 ]]; then
  if [[ $docker_run_err == *"cannot overwrite digest"* ]]; then
    die "could not start the $image container: Docker's local image cache already holds this exact \
tag+digest under a DIFFERENT platform -- almost always because this script's OTHER architecture ran \
against the same image in this same Docker install first. Remove the cached image ('docker rmi' the \
image ID from 'docker images --digests', not the tag -- the tag alone matches both platforms) and \
re-run this tier, or run the two architectures against separate Docker installs (as \
server-packages-acceptance and server-packages-acceptance-aarch64 do in release.yml). Docker said: \
$docker_run_err"
  else
    die "could not start the $image container -- for $arch this usually means qemu-user is not registered \
(docker/setup-qemu-action in CI, or locally: docker run --rm --privileged tonistiigi/binfmt --install arm64). \
Docker said: $docker_run_err"
  fi
fi

dexec() { "$docker" exec "$container" "$@"; }
dexec_i() { "$docker" exec -i "$container" "$@"; }

# THE ARCHITECTURE SELF-CHECK, before a single other thing touches this
# container -- `--platform` above is a REQUEST, not a guarantee. A Docker
# install whose image cache already holds a DIFFERENT platform under this
# exact tag+digest (measured on this very machine while reviewing this
# script: an aarch64 run left `rockylinux/rockylinux:8@sha256:e8a49c54...`
# resolved to arm64 in the local cache, and the very next x86_64 run then
# silently started an arm64 container under that same pinned reference,
# with nothing louder than a line on stderr this script never reads) can
# satisfy `docker run` from the wrong platform without a word of
# complaint. Left unchecked, the daemon's own package manager eventually
# notices -- `dnf`/`dpkg` refusing a foreign-architecture package -- but by
# then the failure names "a broken package", which is exactly backwards.
# A container silently on the wrong architecture is the same defect class
# this whole slice exists to hunt: something that does not do what it
# claims, and says nothing about it.
actual_machine=$(dexec uname -m) ||
  die "could not even read $container's own architecture (uname -m) -- it may not have started on \
$expected_platform at all"
[[ $actual_machine == "$expected_machine" ]] ||
  die "$container is running $actual_machine, not $expected_machine: $image resolved to the wrong \
platform for this tier. The usual cause is a Docker image cache that already holds a DIFFERENT \
platform under this exact tag+digest -- remove it ('docker rmi' the cached image ID, not just the \
tag) and pull it again with 'docker pull --platform $expected_platform $image' before re-running."
ok "$container is really running $actual_machine"

"$docker" cp "$pkg" "$container:/tmp/$base"

# Validate actual generated metadata before a base image's preinstalled tools
# can hide a missing maintainer-script dependency.
case $fmt in
  deb)
    dependencies=$(dexec dpkg-deb -f "/tmp/$base" Depends) || die "could not query Debian dependencies"
    ;;
  rpm)
    dependencies=$(dexec rpm -qp --qf '[%{REQUIRENAME}\t%{REQUIREFLAGS}\n]' "/tmp/$base") ||
      die "could not query RPM dependency flags"
    ;;
esac
printf '%s\n' "$dependencies" | bash "$root/packaging/check-maintainer-dependencies.sh" "$fmt" ||
  die "$base lacks required account-creation dependencies"
ok "generated maintainer-script dependencies are present"

case $fmt in
  deb)
    dexec sh -c 'export DEBIAN_FRONTEND=noninteractive; dpkg -i "$1" || true; apt-get update -qq && apt-get -f install -y -qq' _ "/tmp/$base" \
      || die "$base did not install cleanly (dpkg -i + apt-get -f install)"
    ;;
  rpm)
    dexec dnf install -y "/tmp/$base" || die "$base did not install cleanly (dnf install)"
    ;;
esac
ok "$base installed"

dexec sh -c 'getent passwd qshd >/dev/null' ||
  die "the qshd system account was not created by the postinst"
ok "account qshd exists"

dexec sh -c '[ -f /etc/pam.d/qshd ]' ||
  die "/etc/pam.d/qshd is missing after install -- the package's own PAM service file"
ok "/etc/pam.d/qshd is present"

# Test the configuration that ships, not a hand-written equivalent. Compare
# on the host: minimal package-floor images need not contain diffutils.
profile=debian
if [[ $fmt == rpm ]]; then profile=fedora; fi
pam_snapshot=$(mktemp)
"$docker" cp "$container:/etc/pam.d/qshd" "$pam_snapshot" ||
  die "could not copy the installed PAM service for byte comparison"
cmp -s "$root/packaging/pam.d/qshd.$profile" "$pam_snapshot" ||
  die "installed PAM service differs from this checkout's package profile"
rm -f "$pam_snapshot"
pam_snapshot=
ok "installed PAM profile matches the source bytes"

dexec sh -c '[ -f /usr/lib/systemd/system/qshd.service ]' ||
  die "/usr/lib/systemd/system/qshd.service is missing after install"
ok "the system unit file is present"
if dexec sh -c 'command -v systemd-analyze >/dev/null 2>&1'; then
  dexec systemd-analyze verify /usr/lib/systemd/system/qshd.service ||
    die "systemd-analyze verify complains about the shipped unit file"
  ok "systemd-analyze verify is clean (no systemd started -- this is static analysis only)"
else
  ok "systemd-analyze is not in this image -- skipped, as design §11 allows"
fi

if [[ $arch == aarch64 ]]; then
  # The cheap tier's second and last property: the binary actually
  # executes on this architecture (not a build artifact nobody ran), and
  # refuses rather than falls through to /etc/pam.d/other when its own
  # service file is missing -- the one property that is architecture-
  # independent enough to be worth checking twice, and cheap enough
  # (`timeout`, no accounts, no network probe) that checking it twice
  # costs nothing next to an emulated login.
  dexec rm -f /etc/pam.d/qshd
  set +e
  refusal=$(dexec timeout 10 /usr/bin/qshd serve --system --port 61022 2>&1 >/dev/null)
  status=$?
  set -e
  [[ $status -ne 0 ]] ||
    die "the daemon must refuse to start without /etc/pam.d/qshd, yet it exited 0 under emulation"
  [[ $status -ne 124 ]] ||
    die "the daemon must refuse before it binds anything -- it ran the full 10s timeout under emulation instead"
  case $refusal in
    *"/etc/pam.d/qshd"*) ;;
    *) die "the refusal must name the missing file /etc/pam.d/qshd; got: $refusal" ;;
  esac
  ok "the daemon refuses to start without its PAM service file (exit $status), under $arch emulation"
  say "$fmt/$arch: cheap tier complete -- install and the PAM-less refusal, nothing else"
  exit 0
fi

# ---------------------------------------------------------------------------
# The full tier, x86_64 only: real logins over the real wire protocol.
# ---------------------------------------------------------------------------
client_target=x86_64-unknown-linux-musl
native_uapi=$(mktemp -d)
ln -s /usr/include/linux "$native_uapi/linux"
ln -s /usr/include/asm-generic "$native_uapi/asm-generic"
ln -s "/usr/include/$(gcc -dumpmachine)/asm" "$native_uapi/asm"
native_prefix=$(bash "$root/scripts/build-openssl.sh" --target "$client_target" \
  --cache "${CARGO_TARGET_DIR:-$root/target}/native-crypto" \
  --cflag=-idirafter --cflag="$native_uapi" --jobs 2)
export OPENSSL_DIR="$native_prefix" OPENSSL_STATIC=1
say "building acceptance_client for $client_target (host cargo, never shipped)"
( cd "$root" && cargo build -p qshd --example acceptance_client --locked --release --target "$client_target" ) ||
  die "acceptance_client did not build -- needs a Rust toolchain with the $client_target target on this machine"
client_bin="$root/target/$client_target/release/examples/acceptance_client"
[[ -x $client_bin ]] || die "expected $client_bin after the build; it is not there"
"$docker" cp "$client_bin" "$container:/usr/local/bin/acceptance_client"

# One account per PAM family's own service file -- Debian's is what's
# shipped on this floor, Fedora's is exercised by the rpm run of this same
# script. `--create-home` because the daemon's helper reads
# `%h/.ssh/authorized_keys`.
make_account() {
  local name=$1
  dexec useradd --create-home --shell /bin/sh "$name" || die "useradd $name failed"
  dexec mkdir -p "/home/$name/.ssh"
  local pub
  pub=$(dexec /usr/local/bin/acceptance_client genkey "/home/$name/.private_key") ||
    die "genkey for $name failed"
  printf '%s\n' "$pub" | dexec_i sh -c "cat > /home/$name/.ssh/authorized_keys"
  dexec sh -c "chown -R $name:$name /home/$name/.ssh && chmod 700 /home/$name/.ssh && chmod 600 /home/$name/.ssh/authorized_keys"
}
make_account alice
make_account bob

# These fresh containers never run systemd-user-sessions to remove the
# image's boot marker. Complete fixture boot before the normal login controls;
# the explicit nologin checks below still install and test both policy markers.
dexec rm -f /run/nologin

say "starting the installed /usr/bin/qshd serve --system directly, as root"
port=$((20000 + (RANDOM % 20000)))
dexec sh -c "nohup /usr/bin/qshd serve --system --port $port >/tmp/daemon.out 2>/tmp/daemon.err </dev/null &"

wait_for_banner() {
  local deadline=$((SECONDS + 15))
  while ((SECONDS < deadline)); do
    if dexec sh -c '[ -s /tmp/daemon.out ]' 2>/dev/null; then
      local line
      line=$(dexec sh -c 'head -n 1 /tmp/daemon.out')
      if [[ $line == server-pubkey:* ]]; then
        printf '%s' "${line#server-pubkey: }"
        return 0
      fi
    fi
    sleep 0.2
  done
  return 1
}
server_pub=$(wait_for_banner) ||
  die "the installed daemon never printed its startup banner; stderr: $(dexec cat /tmp/daemon.err 2>/dev/null || true)"
ok "daemon serving on port $port, server-pubkey $server_pub"

probe() {
  dexec /usr/local/bin/acceptance_client probe --port "$port" --server-pub "$server_pub" "$@"
}
log_count() {
  # 0, not a failure, when the log has nothing matching yet -- the daemon
  # creates the file at startup (`log::init`), so a missing file at this
  # point would itself be worth failing on, but every call site here
  # follows a check that already proved the daemon is up.
  dexec sh -c "grep -cE -- \"\$1\" /var/log/qshd/qshd.log 2>/dev/null || true" _ "$1"
}
key_of() { printf '/home/%s/.private_key' "$1"; }
# The start of a whole `qshd.log` line, as an extended regex: the shared
# header `YYYY-MM-DD HH:MM:SS.mmm UTC [pid] LEVEL component: `, level padded
# to five characters. `log_header WARN helper` -> `^... \[[0-9]+\] WARN  helper: `.
log_header() {
  printf '^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3} UTC \\[[0-9]+\\] %-5s %s: ' "$1" "$2"
}

# --- two real accounts, each a shell running as itself ------------------
say "alice and bob each log in and run \`id -un\` as themselves"
for name in alice bob; do
  out=$(probe --key "$(key_of "$name")" --login "$name" --command "id -un" --timeout-secs 10) ||
    die "$name's login must succeed; got: $out"
  case $out in
    RESULT=opened\ exit=0\ output=*"$name"*) ;;
    *) die "$name's \`id -un\` must print $name and exit 0; got: $out" ;;
  esac
  ok "$name: $out"
done

# --- package PAM policy on executed commands ---------------------------
say "new logins receive audit identity and per-account limits"
policy_report='printf "policy_uid=%s audit=%s soft=%s hard=%s\n" "$(id -u)" "$(cat /proc/self/loginuid)" "$(ulimit -Sn)" "$(ulimit -Hn)"'
bob_before=$(probe --key "$(key_of bob)" --login bob --command "$policy_report" --timeout-secs 10) ||
  die "unaffected account baseline failed: $bob_before"
dexec sh -c 'test ! -e /etc/security/limits.d/99-qshd-policy-acceptance.conf' ||
  die "limits fixture collision"
printf 'alice soft nofile 73\nalice hard nofile 73\n' |
  dexec_i sh -c 'mkdir -p /etc/security/limits.d; cat > /etc/security/limits.d/99-qshd-policy-acceptance.conf'
alice_uid=$(dexec id -u alice)
policy_out=$(probe --key "$(key_of alice)" --login alice --command "$policy_report" --timeout-secs 10) ||
  die "policy login failed: $policy_out"
[[ $policy_out == RESULT=opened\ exit=0\ output=*"policy_uid=$alice_uid audit=$alice_uid soft=73 hard=73"* ]] ||
  die "executed audit identity/limits are wrong: $policy_out"
bob_after=$(probe --key "$(key_of bob)" --login bob --command "$policy_report" --timeout-secs 10) ||
  die "unaffected account control failed: $bob_after"
[[ $bob_after == "$bob_before" ]] || die "alice's policy changed bob's context: $bob_before -> $bob_after"
ok "account audit UID and limits reach exec without changing the other account"
dexec rm /etc/security/limits.d/99-qshd-policy-acceptance.conf

say "both nologin markers refuse a new PAM session"
dexec sh -c 'test ! -e /etc/nologin && test ! -e /run/nologin' ||
  die "nologin fixture collision"
ordinal=0
for marker in /etc/nologin /run/nologin; do
  ordinal=$((ordinal + 1))
  # Unique known token abbreviations correlate the helper verdict to this
  # Open; route retirement can race delivery of the wire Refused record.
  prefix=$(printf '%04x' "$((0x5700 + ordinal))")
  policy_token=$(printf '%s%028x' "$prefix" "$ordinal")
  pattern="login session setup failed $prefix\\.\\. at channel [0-9]+: pam_acct_mgmt:"
  [[ $(log_count "$pattern") == 0 ]] || die "policy token abbreviation collision"
  printf 'Disposable package acceptance\n' | dexec_i sh -c 'cat > "$1"' _ "$marker"
  if refused_out=$(probe --key "$(key_of alice)" --login alice --token "$policy_token" \
      --command "printf 'policy-forbidden-%s' execution" --timeout-secs 6); then
    die "$marker must refuse a new login: $refused_out"
  else
    probe_code=$?
  fi
  [[ $probe_code == 2 || $probe_code == 3 ]] || die "probe failed unexpectedly ($probe_code): $refused_out"
  [[ $refused_out != *RESULT=opened* && $refused_out != *policy-forbidden-execution* ]] ||
    die "$marker allowed command execution: $refused_out"
  [[ $(log_count "$pattern") == 1 ]] ||
    die "$marker produced no exact-session PAM account refusal (a timeout alone is not evidence)"
  dexec rm "$marker"
  restored=$(probe --key "$(key_of alice)" --login alice \
    --command "printf 'policy-restored-%s' execution" --timeout-secs 10) ||
    die "login did not recover after removing $marker: $restored"
  [[ $restored == RESULT=opened\ exit=0\ output=*policy-restored-execution* ]] ||
    die "missing executed positive control after $marker: $restored"
  ok "$marker: exact-session PAM refusal and restored admission (client-visible delivery is outside this check)"
done

# --- §10: the accept line, whole shape, for each account -----------------
say "checking the §10 accept line's exact shape (not a substring) for both logins"
for name in alice bob; do
  pattern="$(log_header INFO helper)Accepted signature for $name from 127\\.0\\.0\\.1:[0-9]+ key ED25519 SHA256:[A-Za-z0-9+/]+=*\$"
  count=$(log_count "$pattern")
  [[ $count -ge 1 ]] ||
    die "no line of the shape 'Accepted signature for $name from <addr>:<port> key ED25519 SHA256:<fingerprint>' \
in the daemon's log; changing one word of §10's contract must fail exactly here. Log:
$(dexec cat /var/log/qshd/qshd.log)"
  ok "$name: the accept line matches §10 exactly ($count occurrence(s))"
done

# --- §10: both refusal shapes ---------------------------------------------
say "checking §10's two refusal shapes: an unknown login, and a known one with the wrong key"
unknown_out=$(probe --key "$(key_of alice)" --login qshd-accept-no-such-user --command "id -un" --timeout-secs 6) || true
case $unknown_out in
  RESULT=opened*) die "an unlisted login name must be refused, not opened; got: $unknown_out" ;;
esac
pattern="$(log_header WARN helper)"'Failed signature for invalid user qshd-accept-no-such-user from 127\.0\.0\.1:[0-9]+$'
[[ $(log_count "$pattern") -ge 1 ]] ||
  die "no line of the shape 'Failed signature for invalid user <name> from <addr>:<port>' for an unknown login. Log:
$(dexec cat /var/log/qshd/qshd.log)"
ok "unknown login: refused, and logged as §10's 'invalid user' shape"

wrongkey_out=$(probe --key "$(key_of alice)" --login bob --command "id -un" --timeout-secs 6) || true
case $wrongkey_out in
  RESULT=opened*) die "alice's key claiming to be bob must be refused, not opened; got: $wrongkey_out" ;;
esac
pattern="$(log_header WARN helper)"'Failed signature for bob from 127\.0\.0\.1:[0-9]+$'
[[ $(log_count "$pattern") -ge 1 ]] ||
  die "no line of the shape 'Failed signature for <name> from <addr>:<port>' for a known account whose key did \
not verify. Log:
$(dexec cat /var/log/qshd/qshd.log)"
ok "known account, wrong key: refused, and logged as §10's non-'invalid user' shape"

# --- the main event: bob presenting alice's token ------------------------
say "THE SECURITY REGRESSION TEST: bob, holding alice's live session token, must get refused -- never her shell"
fixed_token=$(dexec sh -c 'head -c16 /dev/urandom | od -An -tx1 | tr -d " \n"')
[[ ${#fixed_token} -eq 32 ]] || die "could not make a 32-hex-char token (got ${#fixed_token} chars: $fixed_token)"

alice_out_file=$(mktemp)
# Alice's own login, forced onto $fixed_token and held open for a few
# seconds with a real running command: a channel that opened and closed in
# the time it takes to say so would already be gone (the graceful close
# ends the login -- see `qshd/tests/system_mode_pam.rs`'s own
# `a_session_is_closed_when_the_login_ends`) by the time bob's attempt
# reached the daemon, and bob would legitimately win a now-abandoned token
# rather than collide with a live session -- proving nothing.
( probe --key "$(key_of alice)" --login alice --token "$fixed_token" --command "id -un && sleep 5" --timeout-secs 15 >"$alice_out_file" 2>&1 ) &
alice_pid=$!
sleep 2

bob_out=$(probe --key "$(key_of bob)" --login bob --token "$fixed_token" --command "id -un" --timeout-secs 6) || true
case $bob_out in
  RESULT=opened*)
    die "SECURITY REGRESSION: bob, presenting alice's token, opened a channel -- got: $bob_out"
    ;;
esac
ok "bob's colliding-token attempt did not open a channel: $bob_out"

pattern='its login is already bound to a different account'
[[ $(log_count "$pattern") -ge 1 ]] ||
  die "bob's attempt must be refused BECAUSE the token's owner does not match -- expected the helper's own \
'$pattern' line, found none. Log:
$(dexec cat /var/log/qshd/qshd.log)"
ok "the daemon's log names the reason: the token is bound to a different account"

wait "$alice_pid" || true
alice_out=$(cat "$alice_out_file")
rm -f "$alice_out_file"
case $alice_out in
  RESULT=opened\ exit=0\ output=*alice*) ;;
  *) die "alice's own session must run to completion, undisturbed by bob's attempt; got: $alice_out" ;;
esac
ok "alice's session ran to completion undisturbed: $alice_out"
say "security regression test passed: bob never got alice's session, and alice's was never touched"

# --- the daemon refuses to start without its own PAM service file --------
say "the installed daemon refuses to start with /etc/pam.d/qshd taken away"
dexec pkill -f 'qshd serve' >/dev/null 2>&1 || true
sleep 1
dexec cp /etc/pam.d/qshd /tmp/qshd.pam.backup
dexec rm -f /etc/pam.d/qshd
set +e
refusal=$(dexec timeout 10 /usr/bin/qshd serve --system --port $((port + 1)) 2>&1 >/dev/null)
status=$?
set -e
dexec cp /tmp/qshd.pam.backup /etc/pam.d/qshd
[[ $status -ne 0 ]] ||
  die "the daemon must refuse to start without /etc/pam.d/qshd, yet it exited 0"
[[ $status -ne 124 ]] ||
  die "the daemon must refuse before it binds anything -- it ran the full 10s timeout instead of exiting"
case $refusal in
  *"/etc/pam.d/qshd"*) ;;
  *) die "the refusal must name the missing file /etc/pam.d/qshd; got: $refusal" ;;
esac
ok "the daemon refuses to start without its PAM service file (exit $status), naming the missing file"

say "$fmt/$arch: full tier complete -- every check passed"
